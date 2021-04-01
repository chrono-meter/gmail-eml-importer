r"""Email import tool for Gmail.
"""
__author__ = __author_email__ = 'chrono-meter@gmx.net'
__license__ = 'GPLv3'
__version__ = '20210402'

import logging
import io
from pathlib import Path, PurePosixPath
import socket
import email, email.feedparser, email.message
import re
import json
import hashlib

# pip install google-auth google-api-python-client
from google.oauth2 import service_account
import googleapiclient.discovery
import googleapiclient.http
import googleapiclient.errors


class App:
    args = None
    gmail = None  # https://developers.google.com/resources/api-libraries/documentation/gmail/v1/python/latest/index.html
    root = None
    label_name_to_id_map = None
    retry_queue = None

    def __call__(self, args):
        self.args = args
        logging.info(self.args)

        if self.args.service_account_file:
            # https://developers.google.com/identity/protocols/oauth2/service-account
            # https://admin.google.com/ac/owl/domainwidedelegation

            logging.info(f'service account file is {self.args.service_account_file}')
            credentials = service_account.Credentials.from_service_account_file(
                self.args.service_account_file,
                scopes=[
                    # 'https://www.googleapis.com/auth/gmail.readonly',
                    'https://www.googleapis.com/auth/gmail.modify',
                ],
            )

            logging.info(f'user is {self.args.user}')
            delegated_credentials = credentials.with_subject(self.args.user)

        else:
            # https://developers.google.com/people/quickstart/python
            raise NotImplementedError('TODO oauth2')

        self.gmail = googleapiclient.discovery.build('gmail', 'v1', credentials=delegated_credentials)

        # retrieve labels
        results = self.gmail.users().labels().list(userId='me').execute()
        self.label_name_to_id_map = {label['name']: label['id'] for label in results['labels']}
        logging.debug(f'initial labels are {self.label_name_to_id_map}')

        self.root = Path(self.args.directory)
        self.retry_queue = []
        self._iter_dir(self.root)

        for i in range(self.args.max_retry):

            if self.retry_queue:
                logging.warning(f'retry {i + 1}/{self.args.max_retry} started, {len(self.retry_queue)} files are queued')

                for file in self.retry_queue:
                    self._proc_file(file)

        if self.retry_queue:
            logging.warning(f'retry exceeded, {len(self.retry_queue)} files are queued')
            for file in self.retry_queue:
                logging.warning(f'queued {file}')

    def _iter_dir(self, directory: Path):
        for item in directory.iterdir():
            if item.is_dir():
                self._iter_dir(item)
            else:
                self._proc_file(item)

    def _proc_file(self, file: Path):
        try:
            self._import_eml(file)

        except googleapiclient.errors.HttpError as e:
            if str(e.resp.status)[:1] == '5':
                logging.exception(f'service error, retry queued {file}', exc_info=True)
                self.retry_queue.append(file)
            else:
                logging.exception(f'import error {file}', exc_info=True)

        except (socket.herror, socket.gaierror, socket.timeout, googleapiclient.errors.HttpError):
            logging.info(f'network error, retry queued {file}', exc_info=True)
            self.retry_queue.append(file)

        except Exception:
            logging.exception(f'import error {file}', exc_info=True)

    def _normalize_label_name(self, label_name):
        """Normalize label name to Gmail label name format.
        Note that there is no way to search label by string.
        """
        return re.sub('\s+', ' ', label_name)

    def _create_label(self, label_name: str) -> str:
        """Get or create label id by name.
        """
        label = PurePosixPath(self._normalize_label_name(label_name))

        # check label exists else create label
        for part in [str(_) for _ in list(reversed(label.parents))[1:] + [label]]:
            if part not in self.label_name_to_id_map:
                logging.debug(f'label {part} is not found')

                try:
                    result = self.gmail.users().labels().create(
                        userId='me',
                        body={'name': part}
                    ).execute()
                except googleapiclient.errors.HttpError as e:
                    if e.resp.status == 409:
                        logging.error(f'Unhandlable, failed to create label {part}. Gmail label normazlization method is not opend.')
                        # from pprint import pprint
                        # pprint([part, self.label_name_to_id_map])
                        # import pdb; pdb.set_trace()
                    raise

                self.label_name_to_id_map[result['name']] = result['id']

                logging.debug(f'label {part} is created as {result}')

        return self.label_name_to_id_map[str(label)]

    def _parse_message(self, content: bytes):
        # NOTE I found some message files starts with BASE64 encoded lines, non headers. Some MUA (Outlook, Thunderbird) can show these files, but all attachemnets are broken. These files may be corrupted.

        # return email.message_from_bytes(content)

        fp = io.StringIO(content.decode('ASCII', errors='surrogateescape'))
        leader = []

        # cut non? mime format leader lines
        while line := fp.readline():
            if email.feedparser.headerRE.match(line):
                fp.seek(fp.tell() - len(line))  # rewind a line
                break
            leader.append(line.rstrip('\r\n'))

        if leader:
            leader.append('')

        # NOTE serialization comparison is sometimes fail, because long lines are splitted into multi lines.
        class MessageWithLeader(email.message.Message):

            def as_string(self, unixfrom=False, maxheaderlen=0, policy=None):
                policy = self.policy if policy is None else policy
                return policy.linesep.join(self.leader) + super().as_string(unixfrom=unixfrom, maxheaderlen=maxheaderlen, policy=policy)

            def as_bytes(self, unixfrom=False, policy=None):
                policy = self.policy if policy is None else policy
                return policy.linesep.join(self.leader).encode() + super().as_bytes(unixfrom=unixfrom, policy=policy)

        eml = email.message_from_file(fp)
        result = MessageWithLeader()
        result.__dict__ = dict(eml.__dict__, leader=leader)
        return result

    def _import_eml(self, file: Path):
        if file.suffix.lower() != '.eml':
            logging.info(f'Skipped, {file} is not a message file.')
            return

        label_name = (Path(self.args.root_tag) / file.relative_to(self.root).parent).as_posix()
        label_id = self._create_label(label_name)
        file_content = file.read_bytes()
        eml = self._parse_message(file_content)

        # generate Message-ID if not exists
        if 'message-id' not in eml:
            for header_key in ('X-MailStore-Message-ID', ):
                if header_key in eml:
                    eml['Message-ID'] = eml[header_key]
                    logging.warning(f'message-id is copied from {header_key} at {file}')
                    break

            else:
                headers = {k: eml[k] for k in sorted(eml.keys()) if k.lower() in 'date subject from to cc bcc'.split()}

                if not headers:
                    logging.error(f'Malformed message file {file}')
                    return

                eml['Message-ID'] = '<' + hashlib.new('sha512', json.dumps(headers).encode()).hexdigest() + '@headerhash.localhost>'

                logging.warning(f'message-id is generated {eml["message-id"]} at {file}')

            file_content = bytes(eml)

        def export_to_gmail():
            # https://stackoverflow.com/a/60087879/3622941
            result = self.gmail.users().messages().insert(
                userId='me',
                body={
                    # 'internalDate': '',  # The internal message creation timestamp (epoch ms)
                    'labelIds': [label_id],
                },
                media_body=googleapiclient.http.MediaIoBaseUpload(io.BytesIO(file_content), mimetype='message/rfc822', resumable=True),
                internalDateSource='dateHeader',  # internalDate will be created from media_body data, not from insert api called time
            ).execute()
            logging.info(f'Success, message {result["id"]} created from {file}')

        # check already imported .eml file
        if 'message-id' in eml:
            result = self.gmail.users().messages().list(
                userId='me',
                q=f'rfc822msgid:{eml["message-id"]}',
            ).execute()

            try:
                imported_message = result['messages'][0]
            except LookupError:
                logging.debug(f'message-id {eml["message-id"]} is not found in gmail')
                export_to_gmail()

            else:
                logging.debug(f'message-id {eml["message-id"]} is found in gmail')

                result = self.gmail.users().messages().get(
                    userId='me',
                    id=imported_message['id'],
                    format='metadata',
                ).execute()
                # import pprint; pprint.pprint(result)

                # check label associated else add label
                if 'labelIds' in result and label_id not in result['labelIds']:
                    self.gmail.users().messages().modify(
                        userId='me',
                        id=imported_message['id'],
                        body={'addLabelIds': [label_id]},
                    ).execute()
                    logging.info(f'Success, message {imported_message["id"]} found from {file}, {label_name} is added')

                else:
                    logging.info(f'Skipped, message {imported_message["id"]} is already imported from {file}')

        else:
            logging.warning(f'message-id is not found in {file}')
            export_to_gmail()


if __name__ == '__main__':
    import argparse

    def validate_file_exists(v):
        if not Path(v).exists():
            raise FileNotFoundError(v)
        return v

    def validate_directory(v):
        validate_file_exists(v)
        if not Path(v).is_dir():
            raise NotADirectoryError(v)
        return v

    def validate_email(v):
        if not email.utils.parseaddr(v)[1]:
            raise ValueError(f'{v} is not valid email address format.')
        return v

    def config_logging_level(v):
        logging.basicConfig(level=logging.__dict__[v])
        return v

    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0].strip())
    parser.add_argument('--service-account-file', type=validate_file_exists,
                        help='path for downloaded service account json file')
    parser.add_argument('--user', type=validate_email,
                        help='email address (Gmail user account name, if you use service account)')
    parser.add_argument('--root-tag', default='IMPORTED',
                        help='root tag name for imported messages (default: %(default)s)')
    parser.add_argument('--logging-level', type=config_logging_level,
                        help='logging level, CRITICAL|ERROR|WARNING|INFO|DEBUG|NOTSET (default: NOTSET)')
    parser.add_argument('--directory', type=validate_directory,
                        help='target directory that contains email message files (directory structure is keeped as tag)')
    parser.add_argument('--max-retry', type=int, default=5,
                        help='max retry count if network error (default: %(default)s)')
    # TODO --overwrite-method=overwrite|ignore|set-label

    args = parser.parse_args()
    app = App()

    app(args)

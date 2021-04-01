# gmail-eml-importer

## Setup

```
pip install google-auth google-api-python-client
```

[Create service account](https://developers.google.com/identity/protocols/oauth2/service-account) with scope *https://www.googleapis.com/auth/gmail.modify*. Currently normal OAuth2 is not supported.

## Usage
```
usage: gmail-eml-importer.py [-h] [--service-account-file SERVICE_ACCOUNT_FILE] [--user USER] [--root-tag ROOT_TAG] [--logging-level LOGGING_LEVEL] [--directory DIRECTORY] [--max-retry MAX_RETRY]

Email import tool for Gmail.

optional arguments:
  -h, --help            show this help message and exit
  --service-account-file SERVICE_ACCOUNT_FILE
                        path for downloaded service account json file
  --user USER           email address (Gmail user account name, if you use service account)
  --root-tag ROOT_TAG   root tag name for imported messages (default: IMPORTED)
  --logging-level LOGGING_LEVEL
                        logging level, CRITICAL|ERROR|WARNING|INFO|DEBUG|NOTSET (default: NOTSET)
  --directory DIRECTORY
                        target directory that contains email message files (directory structure is keeped as tag)
  --max-retry MAX_RETRY
                        max retry count if network error (default: 5)
```

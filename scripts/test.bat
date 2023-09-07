docker run --rm -v %cd%:/usr/src/app -w /usr/src/app python:3.10-alpine sh -c ^
"pip install tox black pylint -rrequirements.txt -rtest-requirements.txt && ^
(black . ; pylint app/ ; tox -e py310)"
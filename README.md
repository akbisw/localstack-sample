# localstack-sample

To recreate error

1. cdk setup
```
cd cdk
mkdir .venv
pipenv install --dev
```

2. bootstrap localstack

```
pipenv run cdklocal bootstrap --app development/app.py
```

3. Deploy cdk
```
pipenv run cdklocal deploy --all --app development/app.py --require-approval never
```

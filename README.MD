# Heroku log drainer

This log drainer transfers heroku logs to aws cloudwatch. The drainer runs on aws lambda. The installation of the lambda is performed via serverless.

# Deploy the log drainer serverless #

1. Configure aws-cli
2. Install serverless

    npm install -g serverless
    npm install
    
3. Install pyenv

    curl https://pyenv.run | bash
    pyenv install 3.7.3
    pyenv virtualenv 3.7.3 log-drainer-for-heroku-to-cloudwatch
    pyenv activate log-drainer-for-heroku-to-cloudwatch

4. Deploy

    serverless deploy

5. Add drain to your heroku app

    heroku drains:add https://your-end-point-name/prod/lambda_handler/your-log-group-name/your-log-stream-name -a your-app

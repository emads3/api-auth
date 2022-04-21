## Requirements
* python3
* mailserver for testing

## Installation 
Create a new environment using venv or pipenv:

    virtualenv api_venv

Activate the environment:

    source api_venv/bin/activate

Install the requirements:

    pip install -r requirements.txt

Migrate the DB tables:

    python3 manage.py migrate

Export email variables:

```shell
export EMAIL_HOST='<mail_host_goes_here>';
export EMAIL_HOST_USER='<username_goes_here>';
export EMAIL_HOST_PASSWORD='<mail_password_goes_here>';
export EMAIL_PORT=<mail_port>;
```

You can use a service like [Mailtrap](https://mailtrap.io) or [Mailhog](https://hub.docker.com/r/mailhog/mailhog) on docker


## API documentation:

You can find the API documentation [here](https://documenter.getpostman.com/view/7160040/Uyr8my9L) with different examples of responses, feel free to use cUrl or any library, Postman documentation is flexable to let you choose between multiple HTTP clients. Or you can import the endpoints collection to your own local postman, _however it's better to import the collection to your local postman application in order for the token to be saved automatically after login, that token will later be automatically used for subsequent requests (using postman test scripts)._


### TODO:
* pagination in listing users.
* writing a docker-compose file to containerize the app.
* writing tests for the endpoints.
* localizing error msgs in responses.
* writing a script to seed the DB with test data.

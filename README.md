# Auto Suggest API

This is a simple API that will return a list of suggestions based on a given param.

## Installation

Requires [Go](https://golang.org/doc/install) to run.

1. Clone the repo
2. Run `go mod tidy` to install dependencies
3. Set up your .env variables, this uses a MongoDB database
    1. `MONGO_URI` - The URI to your MongoDB database
    2. `DATABASE` - The name of the database
4. Run `go run main.go` to start the server

## Usage

The API has a few endpoints:

1. `POST /register` - This will register a new user
    1. Body:
        1. `email` - The email of the user
        2. `password` - The password of the user
    - Returns a message and the users API key on success
---
2. `POST /login` - This will login a user
    1. Body:
        1. `email` - The email of the user
        2. `password` - The password of the user
    - Returns a message and the users API key on success
---
3. `GET /suggest/:param` - This will return a list of suggestions based on the given param
    1. Params:
        1. `param` - The param to search for
    - Returns a list of suggestions on success
    - Requires the following headers
        1. `user` - The email of the user
        2. `apikey` - The API key of the user



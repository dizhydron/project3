I'm less familiar with Python, but the following libraries are not native to built in python libraries and need to be installed for the program and test suite to work. Forgive me if the format for these requirements or instructions is incorrect. This is the first project I've worked with in python, or anything related to this assignment before so I'm ignorant of best practices.

1. http.server
2. Crypto.PublicKey.RSA
3. urllib.parse.urlparse
4. urllib.parse.parse_qs
5. base64
6. json
7. jwt
8. datetime
9. requests
10.sqlite3
11.pycryptodome

The following libraries are not used for project 2, but are WIP methods being used to work on project3. Installing them as well may help resolve issues.

1. uuid
2. secrets
3. argon2

To run the code, the provided files must be in the same directory and the methods must be installed in the terminal. Once they are, run the main server with the following command

python server.py

I've found that it usually takes a minute or two for the server to start up so some tests with the test code or the auto grader may fail. If it returns that the requests sent were actively rejected, wait a few minutes and try again.

Once it's running, the auto grader can be run with the following command.

go run main.go project3

The test suite can be run with the following command.

python test3.py

The server must be run first before the gradebot or the test suite in order to create the database. For project 3, they must be run in the following order. Project3.py, Test3.py, and finally the grade bot. Trying to run the gradebot prior to the test suite will cause some issues as required SQL formats require certain processes not be run twice. The database will be generated when the server is first run and will be named "totally_not_my_privateKeys.db"

The script to generate the database file is restricted. As such, the database cannot be dropped if it exists as per requirements of the assignment. Running the server more than once will result in more keys than intended being generated to run the program. In order to test the code more than once, ensure that the file "totally_not_my_privateKeys.db" is deleted manually prior to running the code.

--Further Notes for Project 3--
I encountered 2 issues. First, the gradebot cannot detect the auth_logs table. The auth_logs table is being generated and is saving records as requedsted as can be seen in screenshot C provided in the github. I don't know why the gradebot can't detect it but it is producing the required output.

The server also has a rate limiter, but the gradebot cannot send requests fast enough to test the required limit of 10. I was unable to test it. I don't think I'll be able to get the gradebot to test fast enough but the rate limiter is in place.
Feature 1:

List the top 10 most active host/IP addresses that have accessed the site.

Feature 2:

Identify the 10 resources that consume the most bandwidth on the site

Feature 3:

List the top 10 busiest (or most frequently visited) 60-minute periods

Feature 4:

Detect patterns of three failed login attempts from the same IP address over 
20 seconds so that all further attempts to the site can be blocked for 5 minutes. 
Log those possible security breaches.

Feature 5:

List the top 10 busiest hours. Output can be observed in ./log_output/hours_best.txt 

Implementation:

Code is written in Python

Numpy and Pandas library has been used

Default test inputs given has been used to run and test implementation

Run run.sh on Git Bash from source folder to see the Training results

Run run_tests.sh from ./insight_testsuite to verify your training results. Accuracy
of results can be verfied by observing the number of "test pass" cases both on Git 
Bash and results.txt folder present in ./insight_testsuite 


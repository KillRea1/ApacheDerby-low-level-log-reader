# Apache Derby low-level log viewer
This app is a fork of this issue: https://issues.apache.org/jira/browse/DERBY-5195
This fork allows you to view the logs of all versions, not just up to 10.10, it is also possible to view the broken log file
## Application assembly
Download the required libraries
```
git clone https://github.com/KillRea1/derby_low-level_log_reader.git /opt/derby_low-level_log_reader
cd /opt/derby_low-level_log_reader
wget https://repo1.maven.org/maven2/org/apache/derby/derby/10.10.2.0/derby-10.10.2.0.jar
wget https://repo1.maven.org/maven2/org/apache/derby/derbyclient/10.10.2.0/derbyclient-10.10.2.0.jar
```
U need installed JDK 8 and build application with javac:
```/<path-to-ur-jdk-8>/bin/javac -cp "derbyclient-10.10.2.0.jar:derby-10.10.2.0.jar:." LogFileReader.java```
## Usage example
After building, you need to run the script, here is an example:
```/<path-to-ur-jdk-8>/bin/java LogFileReader <ur dat file> -v > exaple.xml```

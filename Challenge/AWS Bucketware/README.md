# Challenge

**Author**: Hakal  
**Title**: AWS Bucketware  
**Level**: Hard  

---

## Introduction

An attacker used compromised AWS credentials to establish persistence within a cloud environment and propagate large-scale phishing campaigns. In this challenge, as an Incident Responder, you will analyze the various steps taken by the attacker to achieve persistence and set up the staging for phishing campaigns from the compromised environment.

*Inspired by a real-world scenario of actual cloud malware: Ransomware in the Cloud*

---

### Analysis Steps

After following the lab instructions, we need to aggregate all the log files into a single file for easier analysis. To do this, we will use the following command:

```bash
cat *.json > events.json
```

This command concatenates all the JSON log files in the current directory into a single file named `events.json`. This makes it easier to search and analyze the logs using tools like `jq` or any text editor.

![Aggregation of log files](1.png)

---

### Question 1: What is the compromised identity?

To identify the compromised identity, we executed the following command:

```bash
cat events.json | jq '.Records[] | .userIdentity.userName' -c | sort | uniq -c
```

**Explanation of the Command:**
`cat events.json`: Reads the content of the `events.json` file.
`jq '.Records[] | .userIdentity.userName' -c`: Uses jq to parse the JSON and extract the userName field from each record.
`sort`: Sorts the usernames alphabetically.
`uniq -c`: Counts the unique occurrences of each username.

**Output:**
![Compromised IAM user in CloudTrail logs](2.png)

From the output, we can see that the user `s3user` appears 15 times. Given the context of the challenge and the name of the user, we deduce that `s3user` is the compromised identity. This user is likely involved in activities related to S3 buckets, which aligns with the theme of the challenge.

---

### Question 2: In order of occurrence, what were the last three reconnaissance API calls the attacker performed using the compromised credentials?

To identify the last three reconnaissance API calls performed by the attacker using the compromised credentials, we executed the following command:

````bash
cat events.json | jq '.Records[] | select(.userIdentity.userName == "s3user") | .eventName' -c | uniq -c
````

**Explanation of the Command:**

`cat events.json`: Reads the content of the `events.json` file.
`jq '.Records[] | select(.userIdentity.userName == "s3user") | .eventName' -c`: Uses jq to parse the JSON, filter records where the `userName` is `s3user`, and extract the `eventName` field.
`uniq -c`: Counts the unique occurrences of each event name.

**Output:**
![Reconnaissance API calls](3.png)

From the output, we can see that the last three reconnaissance API calls were:

1. `GetBucketVersioning`
2. `ListObjects`
3. `GetObject`

---

### Question 3: What was the first successful reconnaissance API call?

To identify the first successful reconnaissance API call, we executed the following command:

````bash
cat events.json | jq '.Records[] | select(.userIdentity.userName == "s3user") | select(.eventName == "ListBuckets")'
````

**Explanation of the Command:**
`cat events.json`: Reads the content of the events.json file.
`jq '.Records[] | select(.userIdentity.userName == "s3user") | select(.eventName == "ListBuckets")'`: Uses jq to parse the JSON, filter records where the userName is s3user and the eventName is ListBuckets.

**Output:**
![Sucessful API calls](4.png)

From the output, we can see that the first successful reconnaissance API call was `ListBuckets`. This call is significant because it allows the attacker to enumerate all the S3 buckets in the account, which is a crucial step in identifying potential targets for further exploitation. Unlike the other API calls we observed in Question 2, there were no errors associated with this call, indicating it was successfully executed on the first attempt.

---

### Question 4: How did the attacker attempt to maintain persistence within the environment?

To understand how the attacker attempted to maintain persistence within the environment, we executed the following commands:

````bash
cat events.json | jq '.Records[] | .eventName' -c | sort | uniq -c
````

**Explanation of the Command:**
`cat events.json`: Reads the content of the `events.json` file.
`jq '.Records[] | .eventName' -c`: Uses jq to parse the JSON and extract the `eventName` field from each record.
`sort`: Sorts the usernames alphabetically.
`uniq -c`: Counts the unique occurrences of each username.

**Output:**
![Event Name Analysis](5.png)

Next, we filtered the events to focus on the `CreateUser` event:

```bash
cat events.json | jq '.Records[] | select(.eventName == "CreateUser")' -c
```

**Explanation of the Command:**
`cat events.json`: Reads the content of the `events.json` file.
`jq '.Records[] | select(.eventName == "CreateUser")' -c`: Uses jq to parse the JSON and filter records where the eventName is CreateUser.

**Output:**
![CreateUser Attempt](5.png)

From the output, we can see that the attacker attempted to maintain persistence by creating new IAM users. However, the `errorCode` field indicates `AccessDenied`, meaning the attacker did not have the necessary permissions to successfully create new users. Therefore, the attempt to maintain persistence was not successful.

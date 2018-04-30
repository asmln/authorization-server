# authorization-server

curl testclient:testclientsecret@localhost:8080/oauth/token -d grant_type=client_credentials

curl testclient:testclientsecret@localhost:8080/oauth/token -d grant_type=password -d username=user -d password=...
#!/bin/bash

chmod +x /app/wait-for-it.sh

node -e "const mysql=require('mysql2');const host=process.env.MYSQL_HOST||'mysql-db';const port=Number(process.env.MYSQL_PORT||3306);const user=process.env.MYSQL_USER;const password=process.env.MYSQL_PASSWORD;const database=process.env.MYSQL_DATABASE;let attempts=0;const maxAttempts=60;const delay=5000;const tryConnect=()=>{const conn=mysql.createConnection({host,port,user,password,database});conn.connect(err=>{if(!err){conn.end(()=>process.exit(0));return;}conn.destroy();if(++attempts>=maxAttempts){process.exit(1);}setTimeout(tryConnect,delay);});};tryConnect();"

bash startup.sh
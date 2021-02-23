#!/bin/sh

echo "Preparing to run the app's DB setup..."

try_mysql_setup () {
  echo "Trying app DB setup..."

  DBNAME=somedb
  echo "CREATE DATABASE $DBNAME ; " | mysql -u root
  rv=$?

  if [ $rv -eq 0 ]; then

    install_file=/var/www/html/install.sql
    if [ -f $install_file ]; then
      echo "Loading tables..."
      mysql -u root $DBNAME < $install_file
    fi

    echo "App DB setup complete."
  else
    echo "App DB setup incomplete; retrying..."
  fi

  return $rv
}

until try_mysql_setup ; do sleep 2; done

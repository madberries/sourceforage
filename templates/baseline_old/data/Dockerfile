FROM nouphet/docker-php4

COPY pdfdirectory/ /var/www/html
COPY mysql-setup.sh /tmp
COPY run0.sh /tmp
#COPY my.cnf /etc/mysql/
#COPY my.cnf /etc/
COPY create_mysql_users.sh /
COPY php4.ini /etc/php.ini

# Override the image's default run script
# so that we create necessary databases, etc.
CMD ["/bin/bash", "/tmp/run0.sh"]

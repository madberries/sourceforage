FROM mattrayner/lamp:latest-1404-php5

COPY writersBlock/ /app
COPY mysql-setup.sh /tmp
COPY run0.sh /tmp
COPY my.cnf /etc/mysql/

# Override the image's default run script
# so that we create necessary databases, etc.
CMD ["/bin/bash", "/tmp/run0.sh"]

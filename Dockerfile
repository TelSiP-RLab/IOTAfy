FROM php:8.5-apache

# Install system dependencies and SQLite CLI
# Σύμφωνα με το INSTALL απαιτούνται pdo_sqlite, curl, mbstring, json, openssl.
# Εδώ εγκαθιστούμε και libonig-dev (απαιτείται από mbstring) και libcurl4-openssl-dev (για το curl extension).
# Προσθέτουμε sendmail (msmtp) για αποστολή emails μέσω PHP mail().
RUN apt-get update && apt-get install -y \
    sqlite3 \
    libsqlite3-dev \
    libzip-dev \
    libonig-dev \
    libcurl4-openssl-dev \
    msmtp \
    mailutils \
    multitail \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Enable required PHP extensions
# pdo & json & openssl είναι συνήθως ήδη διαθέσιμα, εδώ φροντίζουμε ρητά για pdo_sqlite, mbstring, curl.
RUN docker-php-ext-install pdo pdo_sqlite mbstring curl

# Enable Apache modules needed for .htaccess and headers
RUN a2enmod rewrite headers

# Configure msmtp as sendmail replacement for PHP mail()
# Δημιουργούμε symlink ώστε το PHP mail() να χρησιμοποιεί το msmtp
# Χρησιμοποιούμε -f (force) για να αντικαταστήσουμε οποιοδήποτε υπάρχον sendmail
# Βεβαιωνόμαστε ότι το /usr/sbin υπάρχει και ότι το msmtp είναι executable
RUN mkdir -p /usr/sbin && \
    ln -sf /usr/bin/msmtp /usr/sbin/sendmail && \
    ln -sf /usr/bin/msmtp /usr/bin/sendmail && \
    chmod +x /usr/bin/msmtp && \
    ls -la /usr/sbin/sendmail /usr/bin/sendmail

# Allow .htaccess overrides όπως προτείνει το INSTALL (AllowOverride All, Options -Indexes)
RUN printf "<Directory /var/www/html>\n\
    AllowOverride All\n\
    Require all granted\n\
    Options -Indexes\n\
</Directory>\n" > /etc/apache2/conf-available/iotafy.conf \
    && a2enconf iotafy

# Configure PHP settings σύμφωνα με το INSTALL.el.md (γραμμές 57-62)
# Session security settings
RUN echo "session.cookie_samesite = Lax" >> /usr/local/etc/php/conf.d/iotafy.ini && \
    echo "session.cookie_httponly = On" >> /usr/local/etc/php/conf.d/iotafy.ini && \
    echo "session.cookie_secure = On" >> /usr/local/etc/php/conf.d/iotafy.ini && \
    echo "session.use_strict_mode = 1" >> /usr/local/etc/php/conf.d/iotafy.ini && \
    echo "upload_max_filesize = 16M" >> /usr/local/etc/php/conf.d/iotafy.ini && \
    echo "post_max_size = 32M" >> /usr/local/etc/php/conf.d/iotafy.ini && \
    echo "expose_php = Off" >> /usr/local/etc/php/conf.d/iotafy.ini && \
    echo "sendmail_path = /usr/sbin/sendmail -t -i" >> /usr/local/etc/php/conf.d/iotafy.ini

WORKDIR /var/www/html

# Copy application source code into the container
ADD IOTAfy_Platform/ /var/www/html/

# Make sure required directories exist (they may also be mounted as volumes)
RUN mkdir -p data logs firmware \
    && chown -R www-data:www-data /var/www/html

# Copy entrypoint script
COPY entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 80
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["apache2-foreground"]

FROM php:7.4-apache


# Set working directory
WORKDIR /var/www/
EXPOSE 8001

# Install dependencies and clear cache
# git, unzip & zip are for composer

RUN apt-get update \
    && apt-get install -y \
        unzip \
        zip \
 # https://github.com/docker-library/php/issues/61
        zlib1g-dev \ 
        libzip-dev \ 
        git \
# libonig-dev required for mbstring cf. https://github.com/docker-library/php/issues/880
        libonig-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
# Install extensions
RUN docker-php-ext-install -j$(nproc) pdo_mysql mbstring zip \
    && docker-php-source delete

# XDEBUG
# cf. https://github.com/JetBrains/phpstorm-docker-images/blob/master/php-74-apache-xdebug-29/Dockerfile
EXPOSE 9000
RUN pecl install xdebug-2.9.1 \
    &&  docker-php-ext-enable xdebug \
    && echo "zend_extension=$(find /usr/local/lib/php/extensions/ -name xdebug.so)" > /usr/local/etc/php/conf.d/xdebug.ini;

# Install composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Add user for application
RUN groupadd -g 1000 www
RUN useradd -u 1000 -ms /bin/bash -g www www

COPY apache/sites-available/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY apache/conf-available/z-app.conf /etc/apache2/conf-available/z-app.conf
RUN a2enmod rewrite remoteip && a2enconf z-app

# Copy composer.lock and composer.json
COPY ./phpRp/composer.lock ./phpRp/composer.json /var/www/phpRp/
RUN cd /var/www/phpRp/ \
    && composer install --prefer-dist --no-scripts --no-dev --no-autoloader

COPY ./phpOp/composer.lock ./phpOp/composer.json /var/www/phpOp/
# scripts required for doctrine
RUN cd /var/www/phpOp/ \
    && composer install --prefer-dist --no-dev --no-autoloader \
    && rm -rf ~/.composer


# Copy existing application directory contents

#### /!\ unsecure /!\ ###
COPY . /var/www/
COPY ./phpOp/.env.example /var/www/phpOp/.env

# Copy existing application directory permissions
#### secure ###
#COPY --chown=www:www . /var/www/html

# Grant access to cache
RUN chown www-data:www-data /var/www/phpOp/cache


# Finish composer
RUN cd /var/www/phpRp/ && composer dump-autoload --no-scripts --no-dev --optimize
RUN cd /var/www/phpOp/ && composer dump-autoload --no-scripts --no-dev --optimize

# Change current user to www
#### /!\ unsecure if commented /!\ ###
#USER www

VOLUME [ "/var/www/html" ]
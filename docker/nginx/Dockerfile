FROM nginx:alpine
RUN rm -rf /etc/nginx/conf.d/*
COPY docker/nginx/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80

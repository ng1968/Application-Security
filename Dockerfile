FROM python:3.7
LABEL maintainer="ng1968@nyu.edu"
COPY . /app
WORKDIR /app
RUN make
COPY spell_check your/webroot/
RUN pip install -r your/webroot/requirements.txt
EXPOSE 8080
ENTRYPOINT ["python"]
CMD ["your/webroot//app.py"]

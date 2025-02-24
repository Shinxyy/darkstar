FROM ubuntu:22.04

SHELL ["/bin/bash", "-c"]

# bug fix tzdata 
ENV TZ=Europe/Amsterdam
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    sudo \ 
    wget \
    pipx \
    nano \
    gcc \
    xml2 \
    mariadb-client

RUN mkdir /install
WORKDIR /install

# Install go (https://go.dev/doc/install) -> nuclei
RUN wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz
RUN echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

# Change to the app directory
RUN mkdir /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY main.py /app
COPY setup/requirements.txt /app
COPY modules /app/modules
COPY datasets /app/datasets
COPY c_scripts /app/c_scripts
COPY .env /app
RUN gcc -o c_scripts/search_epss c_scripts/search_epss.c
RUN mkdir /app/bbot_output

# Install any needed packages specified in requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

#? Install Nuclei and bbot
RUN pipx install bbot
RUN echo 'export PATH=$PATH:/root/.local/bin' >> ~/.bashrc

RUN /usr/local/go/bin/go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN echo 'export PATH=$PATH:/root/go/bin/' >> ~/.bashrc

# Directly clone the wordpress templates from wordfence
RUN export GITHUB_TEMPLATE_REPO=topscoder/nuclei-wordfence-cve; /root/go/bin/nuclei -update-templates

CMD ["/bin/bash", "-c", "source /etc/bash.bashrc && tail -f /dev/null"]

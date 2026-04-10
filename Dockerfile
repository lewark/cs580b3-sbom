FROM python:3.11-slim

# Install useful system utilities to allow the LLM agent to interact with the environment
# using its run_command tool mapping
RUN apt-get update && apt-get install -y \
    bash \
    curl \
    wget \
    git \
    tar \
    unzip \
    vim \
    procps \
    net-tools \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install grype vulnerability analysis tool
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install syft vulnerability analysis tool
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Set up the working directory inside the container
WORKDIR /data

# Copy the requirements file and install dependencies natively in the container
# This removes the need for the local 'venv' folder when running inside Docker
COPY requirements_agent.txt /scripts/
RUN pip install --no-cache-dir -r /scripts/requirements_agent.txt

# Copy all the agent scripts and process tools to the container
COPY sbom /scripts/sbom

# Default entry
CMD ["/bin/bash"]

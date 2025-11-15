FROM gitpod/workspace-full:latest

# Install AWS CLI v2
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && sudo ./aws/install \
    && rm -rf aws awscliv2.zip

# Install Terraform
ENV TF_VERSION=1.7.5
RUN curl -fsSL "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_amd64.zip" \
    -o tf.zip \
    && unzip -o tf.zip -d /usr/local/bin \
    && rm tf.zip

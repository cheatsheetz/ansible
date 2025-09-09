# Ansible Cheat Sheet

## Table of Contents
- [Installation and Setup](#installation-and-setup)
- [Inventory Management](#inventory-management)
- [Playbooks](#playbooks)
- [Modules](#modules)
- [Variables](#variables)
- [Ansible Vault](#ansible-vault)
- [Roles](#roles)
- [Best Practices and Security](#best-practices-and-security)
- [Integration with Other Tools](#integration-with-other-tools)
- [Troubleshooting Tips](#troubleshooting-tips)

## Installation and Setup

### Installation Methods
```bash
# Install via pip
pip install ansible

# Install via package manager (Ubuntu/Debian)
sudo apt update
sudo apt install software-properties-common
sudo add-apt-repository --yes --update ppa:ansible/ansible
sudo apt install ansible

# Install via Homebrew (macOS)
brew install ansible

# Install specific version
pip install ansible==6.0.0

# Verify installation
ansible --version
ansible-playbook --version
```

### Configuration
```bash
# Create ansible.cfg file
cat > ansible.cfg << EOF
[defaults]
inventory = ./hosts
remote_user = ansible
private_key_file = ~/.ssh/id_rsa
host_key_checking = False
retry_files_enabled = False
gathering = smart
fact_caching = jsonfile
fact_caching_connection = /tmp/ansible_facts_cache
fact_caching_timeout = 86400

[inventory]
enable_plugins = host_list, script, auto, yaml, ini, toml

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
pipelining = True
EOF

# Environment variables
export ANSIBLE_CONFIG=./ansible.cfg
export ANSIBLE_INVENTORY=./hosts
export ANSIBLE_REMOTE_USER=ansible
```

## Inventory Management

### Static Inventory (INI Format)
```ini
# hosts file
[webservers]
web1.example.com
web2.example.com ansible_host=192.168.1.100
web3.example.com ansible_user=deploy ansible_port=2222

[databases]
db1.example.com
db2.example.com

[loadbalancers]
lb1.example.com
lb2.example.com

# Groups of groups
[production:children]
webservers
databases
loadbalancers

[production:vars]
ansible_user=deploy
ansible_ssh_private_key_file=~/.ssh/prod_key
environment=production

# Host variables
[webservers:vars]
http_port=80
maxRequestsPerChild=808
```

### Static Inventory (YAML Format)
```yaml
# inventory.yml
all:
  children:
    webservers:
      hosts:
        web1.example.com:
        web2.example.com:
          ansible_host: 192.168.1.100
        web3.example.com:
          ansible_user: deploy
          ansible_port: 2222
      vars:
        http_port: 80
        maxRequestsPerChild: 808
    
    databases:
      hosts:
        db1.example.com:
        db2.example.com:
    
    loadbalancers:
      hosts:
        lb1.example.com:
        lb2.example.com:
    
    production:
      children:
        webservers:
        databases:
        loadbalancers:
      vars:
        ansible_user: deploy
        ansible_ssh_private_key_file: ~/.ssh/prod_key
        environment: production
```

### Dynamic Inventory
```python
#!/usr/bin/env python3
# dynamic_inventory.py
import json
import requests

def get_inventory():
    # Example: Fetch from cloud provider API
    inventory = {
        'webservers': {
            'hosts': ['web1.example.com', 'web2.example.com'],
            'vars': {
                'http_port': 80
            }
        },
        '_meta': {
            'hostvars': {
                'web1.example.com': {
                    'ansible_host': '192.168.1.100',
                    'ansible_user': 'ubuntu'
                },
                'web2.example.com': {
                    'ansible_host': '192.168.1.101',
                    'ansible_user': 'ubuntu'
                }
            }
        }
    }
    return inventory

if __name__ == '__main__':
    print(json.dumps(get_inventory(), indent=2))
```

### Inventory Commands
```bash
# List all hosts
ansible all --list-hosts

# List specific group
ansible webservers --list-hosts

# Show inventory graph
ansible-inventory --graph

# Show host variables
ansible-inventory --host web1.example.com

# Test connectivity
ansible all -m ping
ansible webservers -m ping -i inventory.yml

# Run ad-hoc commands
ansible all -m setup
ansible webservers -m command -a "uptime"
ansible databases -m shell -a "df -h"
```

## Playbooks

### Basic Playbook Structure
```yaml
# site.yml
---
- name: Configure web servers
  hosts: webservers
  become: yes
  gather_facts: yes
  vars:
    http_port: 80
    max_clients: 200
  
  tasks:
    - name: Install Apache
      package:
        name: "{{ apache_package }}"
        state: present
    
    - name: Start Apache service
      service:
        name: "{{ apache_service }}"
        state: started
        enabled: yes
    
    - name: Deploy web content
      template:
        src: index.html.j2
        dest: /var/www/html/index.html
        owner: www-data
        group: www-data
        mode: '0644'
      notify: restart apache
  
  handlers:
    - name: restart apache
      service:
        name: "{{ apache_service }}"
        state: restarted

# Variables based on OS family
- name: Set OS-specific variables
  hosts: all
  tasks:
    - name: Include OS-specific variables
      include_vars: "{{ ansible_os_family }}.yml"
```

### Advanced Playbook Features
```yaml
# advanced-playbook.yml
---
- name: Advanced playbook example
  hosts: webservers
  become: yes
  serial: 2  # Process 2 hosts at a time
  max_fail_percentage: 25
  
  pre_tasks:
    - name: Check if maintenance mode is enabled
      stat:
        path: /etc/maintenance
      register: maintenance_mode
    
    - name: Fail if in maintenance mode
      fail:
        msg: "Server is in maintenance mode"
      when: maintenance_mode.stat.exists
  
  tasks:
    - name: Update package cache
      package:
        update_cache: yes
      
    - name: Install packages
      package:
        name: "{{ item }}"
        state: present
      loop:
        - nginx
        - git
        - python3-pip
      
    - name: Configure nginx
      template:
        src: nginx.conf.j2
        dest: /etc/nginx/nginx.conf
        backup: yes
      notify: restart nginx
      tags: config
    
    - name: Deploy application
      git:
        repo: https://github.com/example/app.git
        dest: /var/www/app
        version: "{{ app_version | default('main') }}"
      notify: reload application
      tags: deploy
    
    - name: Wait for service to start
      wait_for:
        port: 80
        timeout: 60
      tags: verify
  
  post_tasks:
    - name: Send notification
      mail:
        to: admin@example.com
        subject: "Deployment completed on {{ inventory_hostname }}"
        body: "Application version {{ app_version }} deployed successfully"
      delegate_to: localhost
  
  handlers:
    - name: restart nginx
      service:
        name: nginx
        state: restarted
    
    - name: reload application
      command: systemctl reload app
```

### Playbook Execution
```bash
# Run playbook
ansible-playbook site.yml

# Run with specific inventory
ansible-playbook -i inventory.yml site.yml

# Run with extra variables
ansible-playbook site.yml -e "app_version=v2.1.0"
ansible-playbook site.yml -e @extra_vars.yml

# Run specific tags
ansible-playbook site.yml --tags config,deploy

# Skip specific tags
ansible-playbook site.yml --skip-tags deploy

# Dry run (check mode)
ansible-playbook site.yml --check

# Show differences
ansible-playbook site.yml --check --diff

# Run on specific hosts
ansible-playbook site.yml --limit webservers
ansible-playbook site.yml --limit "web1.example.com,web2.example.com"

# Start from specific task
ansible-playbook site.yml --start-at-task "Deploy application"

# Verbose output
ansible-playbook site.yml -v    # verbose
ansible-playbook site.yml -vv   # more verbose
ansible-playbook site.yml -vvv  # connection debugging
```

## Modules

### Common Modules
```yaml
# Package management
- name: Install package
  package:
    name: nginx
    state: present

- name: Install specific version
  apt:
    name: nginx=1.18.0-6ubuntu14
    state: present

- name: Install from URL
  dnf:
    name: http://example.com/package.rpm
    state: present

# File operations
- name: Create directory
  file:
    path: /var/www/html
    state: directory
    owner: www-data
    group: www-data
    mode: '0755'

- name: Copy file
  copy:
    src: files/index.html
    dest: /var/www/html/index.html
    owner: www-data
    group: www-data
    mode: '0644'
    backup: yes

- name: Template file
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/nginx.conf
    owner: root
    group: root
    mode: '0644'
  notify: restart nginx

# Service management
- name: Start and enable service
  service:
    name: nginx
    state: started
    enabled: yes

- name: Restart service
  systemd:
    name: nginx
    state: restarted
    daemon_reload: yes

# User management
- name: Create user
  user:
    name: deploy
    group: deploy
    shell: /bin/bash
    home: /home/deploy
    create_home: yes

- name: Add SSH key
  authorized_key:
    user: deploy
    state: present
    key: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}"

# Command execution
- name: Run command
  command: /usr/bin/make install
  args:
    chdir: /tmp/source
    creates: /usr/local/bin/app

- name: Run shell command
  shell: |
    cd /tmp
    wget https://example.com/file.tar.gz
    tar -xzf file.tar.gz
  args:
    creates: /tmp/extracted_file

# Git operations
- name: Clone repository
  git:
    repo: https://github.com/example/repo.git
    dest: /var/www/app
    version: v2.1.0
    force: yes

# Database operations
- name: Create MySQL database
  mysql_db:
    name: myapp
    state: present
    login_user: root
    login_password: "{{ mysql_root_password }}"

- name: Create MySQL user
  mysql_user:
    name: appuser
    password: "{{ app_db_password }}"
    priv: "myapp.*:ALL"
    host: localhost
    state: present
```

### Web and Cloud Modules
```yaml
# HTTP requests
- name: Make HTTP request
  uri:
    url: http://example.com/api/deploy
    method: POST
    body_format: json
    body:
      version: "{{ app_version }}"
      environment: production
    status_code: 200

# AWS modules
- name: Create EC2 instance
  amazon.aws.ec2_instance:
    name: "web-server"
    image_id: ami-0abcdef1234567890
    instance_type: t2.micro
    key_name: my-key
    security_group: web-sg
    region: us-west-2
    state: present

- name: Create S3 bucket
  amazon.aws.s3_bucket:
    name: my-unique-bucket-name
    region: us-west-2
    state: present

# Docker modules
- name: Pull Docker image
  docker_image:
    name: nginx:latest
    source: pull

- name: Run Docker container
  docker_container:
    name: web-container
    image: nginx:latest
    state: started
    ports:
      - "80:80"
    volumes:
      - /var/www/html:/usr/share/nginx/html:ro
```

## Variables

### Variable Definition and Usage
```yaml
# group_vars/all.yml
---
app_name: myapp
app_version: v2.1.0
environment: production

# List variables
packages:
  - nginx
  - git
  - python3-pip

# Dictionary variables
database:
  host: localhost
  port: 3306
  name: myapp
  user: appuser

# host_vars/web1.example.com.yml
---
server_id: 1
local_ip: 192.168.1.100

# Using variables in playbooks
---
- name: Deploy application
  hosts: webservers
  vars:
    app_port: 8080
    debug_mode: false
  
  tasks:
    - name: Install {{ app_name }}
      package:
        name: "{{ item }}"
        state: present
      loop: "{{ packages }}"
    
    - name: Configure database connection
      template:
        src: config.j2
        dest: "/etc/{{ app_name }}/config.yaml"
      vars:
        db_host: "{{ database.host }}"
        db_port: "{{ database.port }}"
```

### Variable Precedence
```yaml
# Variable precedence (highest to lowest):
# 1. extra vars (-e in CLI)
# 2. task vars (only for the task)
# 3. block vars (only for tasks in block)
# 4. role and include vars
# 5. play vars_files
# 6. play vars_prompt
# 7. play vars
# 8. set_facts / registered vars
# 9. host facts / cached set_facts
# 10. playbook host_vars/*
# 11. playbook group_vars/*
# 12. inventory host_vars/*
# 13. inventory group_vars/*
# 14. inventory vars
# 15. role defaults

# Example of setting facts
- name: Set custom facts
  set_fact:
    custom_var: "{{ ansible_hostname }}-custom"
    calculated_value: "{{ (ansible_memtotal_mb * 0.8) | int }}"

# Registering variables
- name: Check service status
  shell: systemctl is-active nginx
  register: service_status
  failed_when: false

- name: Show service status
  debug:
    msg: "Nginx is {{ service_status.stdout }}"
```

### Variable Templating
```jinja2
<!-- templates/nginx.conf.j2 -->
user {{ nginx_user }};
worker_processes {{ ansible_processor_cores }};

upstream backend {
{% for host in groups['webservers'] %}
    server {{ hostvars[host]['ansible_default_ipv4']['address'] }}:{{ app_port }};
{% endfor %}
}

server {
    listen 80;
    server_name {{ ansible_fqdn }};
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

# Environment: {{ environment }}
# Generated on: {{ ansible_date_time.iso8601 }}
```

## Ansible Vault

### Vault Operations
```bash
# Create encrypted file
ansible-vault create secret.yml

# Edit encrypted file
ansible-vault edit secret.yml

# View encrypted file
ansible-vault view secret.yml

# Encrypt existing file
ansible-vault encrypt vars.yml

# Decrypt file
ansible-vault decrypt secret.yml

# Change vault password
ansible-vault rekey secret.yml

# Encrypt string
ansible-vault encrypt_string 'secret_password' --name 'db_password'

# Encrypt with different vault ID
ansible-vault create --vault-id prod@prompt secret-prod.yml
```

### Using Vault in Playbooks
```yaml
# vault.yml (encrypted)
---
$ANSIBLE_VAULT;1.1;AES256
66386439653830656231656636663062346537316531663731653738653437326634643037656333
3637306461613931343466383131323437643936303739650a626537353465663936643435393936
39656465636330373431353338356335306632643133343939656365313935623233343935643366
6566346463653630340a376663653264323133643166373137373536623937366230383466653037
6461

# playbook using vault
---
- name: Deploy with secrets
  hosts: webservers
  vars_files:
    - vault.yml
  
  tasks:
    - name: Configure database
      template:
        src: database.conf.j2
        dest: /etc/myapp/database.conf
      vars:
        db_password: "{{ vault_db_password }}"

# Run playbook with vault
ansible-playbook site.yml --ask-vault-pass
ansible-playbook site.yml --vault-password-file ~/.vault_pass
ansible-playbook site.yml --vault-id @prompt
```

### Multiple Vault IDs
```bash
# Create vaults with different IDs
ansible-vault create --vault-id dev@prompt secrets-dev.yml
ansible-vault create --vault-id prod@prompt secrets-prod.yml

# Use multiple vault IDs
ansible-playbook site.yml --vault-id dev@prompt --vault-id prod@prompt

# Vault password files
echo "dev_password" > .vault_pass_dev
echo "prod_password" > .vault_pass_prod
chmod 600 .vault_pass_*

ansible-playbook site.yml --vault-id dev@.vault_pass_dev --vault-id prod@.vault_pass_prod
```

## Roles

### Role Structure
```
roles/
└── webserver/
    ├── tasks/
    │   └── main.yml
    ├── handlers/
    │   └── main.yml
    ├── templates/
    │   └── nginx.conf.j2
    ├── files/
    │   └── index.html
    ├── vars/
    │   └── main.yml
    ├── defaults/
    │   └── main.yml
    ├── meta/
    │   └── main.yml
    └── README.md
```

### Role Files
```yaml
# roles/webserver/tasks/main.yml
---
- name: Install web server
  package:
    name: "{{ webserver_package }}"
    state: present

- name: Configure web server
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/nginx.conf
  notify: restart nginx

- name: Start web server
  service:
    name: "{{ webserver_service }}"
    state: started
    enabled: yes

# roles/webserver/handlers/main.yml
---
- name: restart nginx
  service:
    name: nginx
    state: restarted

# roles/webserver/defaults/main.yml
---
webserver_package: nginx
webserver_service: nginx
webserver_port: 80

# roles/webserver/vars/main.yml
---
webserver_config_dir: /etc/nginx
webserver_log_dir: /var/log/nginx

# roles/webserver/meta/main.yml
---
galaxy_info:
  author: Your Name
  description: Web server configuration role
  company: Your Company
  license: MIT
  min_ansible_version: 2.9
  platforms:
    - name: Ubuntu
      versions:
        - bionic
        - focal
  galaxy_tags:
    - webserver
    - nginx

dependencies:
  - role: firewall
    vars:
      firewall_rules:
        - port: 80
          proto: tcp
          rule: allow
```

### Using Roles
```yaml
# site.yml
---
- name: Configure web servers
  hosts: webservers
  become: yes
  
  roles:
    - role: common
    - role: webserver
      vars:
        webserver_port: 8080
    - role: monitoring
      when: enable_monitoring | default(false)

# Alternative syntax
- name: Configure servers
  hosts: all
  become: yes
  
  tasks:
    - name: Apply common configuration
      include_role:
        name: common
    
    - name: Configure web server
      include_role:
        name: webserver
      vars:
        webserver_port: 8080
      when: "'webservers' in group_names"
```

### Ansible Galaxy
```bash
# Search for roles
ansible-galaxy search nginx

# Install role
ansible-galaxy install geerlingguy.nginx

# Install from requirements file
# requirements.yml
---
- name: geerlingguy.nginx
  version: 2.8.0
- src: https://github.com/geerlingguy/ansible-role-apache.git
  name: apache
  version: main

ansible-galaxy install -r requirements.yml

# Create role structure
ansible-galaxy init my-role

# List installed roles
ansible-galaxy list

# Remove role
ansible-galaxy remove geerlingguy.nginx
```

## Best Practices and Security

### Security Best Practices
```yaml
# Use become sparingly
- name: Install package
  package:
    name: nginx
    state: present
  become: yes

# Avoid become: yes at play level unless necessary
- name: Configure application
  hosts: webservers
  # become: yes  # Avoid this
  
  tasks:
    - name: Create directory
      file:
        path: /var/www/html
        state: directory
      become: yes  # Use this instead

# Validate input
- name: Validate port number
  assert:
    that:
      - port is defined
      - port | int > 0
      - port | int < 65536
    fail_msg: "Port must be a number between 1 and 65535"

# Use no_log for sensitive data
- name: Set password
  user:
    name: myuser
    password: "{{ user_password | password_hash('sha512') }}"
  no_log: true

# Secure file permissions
- name: Deploy SSH key
  copy:
    src: id_rsa
    dest: ~/.ssh/id_rsa
    owner: "{{ ansible_user }}"
    group: "{{ ansible_user }}"
    mode: '0600'
```

### Code Organization
```yaml
# Use meaningful task names
- name: Install web server packages  # Good
  package:
    name: "{{ item }}"
    state: present
  loop: "{{ webserver_packages }}"

# Not: Install packages  # Bad

# Group related tasks
- name: Web server configuration
  block:
    - name: Install nginx
      package:
        name: nginx
        state: present
    
    - name: Configure nginx
      template:
        src: nginx.conf.j2
        dest: /etc/nginx/nginx.conf
      notify: restart nginx
    
    - name: Start nginx
      service:
        name: nginx
        state: started
        enabled: yes
  
  rescue:
    - name: Handle web server configuration failure
      debug:
        msg: "Web server configuration failed"
  
  always:
    - name: Ensure firewall allows HTTP
      firewalld:
        service: http
        permanent: yes
        state: enabled

# Use tags effectively
- name: Update system packages
  package:
    name: '*'
    state: latest
  tags:
    - packages
    - security

- name: Configure application
  template:
    src: app.conf.j2
    dest: /etc/app/app.conf
  tags:
    - config
    - application
```

## Integration with Other Tools

### CI/CD Integration
```yaml
# .gitlab-ci.yml
stages:
  - validate
  - deploy

validate_ansible:
  stage: validate
  script:
    - ansible-playbook --syntax-check site.yml
    - ansible-lint site.yml

deploy_staging:
  stage: deploy
  script:
    - ansible-playbook -i staging site.yml
  only:
    - develop

deploy_production:
  stage: deploy
  script:
    - ansible-playbook -i production site.yml
  only:
    - main
  when: manual
```

### Terraform Integration
```hcl
# terraform/main.tf
resource "aws_instance" "web" {
  count         = 3
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t2.micro"
  
  tags = {
    Name = "web-${count.index + 1}"
    Type = "webserver"
  }
}

output "web_servers" {
  value = {
    for instance in aws_instance.web :
    instance.tags.Name => instance.public_ip
  }
}

# Generate Ansible inventory
resource "local_file" "ansible_inventory" {
  content = templatefile("${path.module}/inventory.tpl", {
    web_servers = aws_instance.web
  })
  filename = "${path.module}/../ansible/hosts"
}
```

### Docker Integration
```yaml
# Deploy containerized applications
- name: Deploy application stack
  docker_compose:
    project_src: /opt/myapp
    state: present
    build: yes

- name: Run database container
  docker_container:
    name: myapp-db
    image: postgres:13
    state: started
    env:
      POSTGRES_DB: myapp
      POSTGRES_USER: myapp
      POSTGRES_PASSWORD: "{{ db_password }}"
    volumes:
      - myapp-db-data:/var/lib/postgresql/data
    networks:
      - name: myapp-network
```

### Monitoring Integration
```yaml
# Install and configure monitoring agents
- name: Install Prometheus node exporter
  unarchive:
    src: https://github.com/prometheus/node_exporter/releases/download/v1.3.1/node_exporter-1.3.1.linux-amd64.tar.gz
    dest: /opt
    remote_src: yes
    creates: /opt/node_exporter-1.3.1.linux-amd64

- name: Create systemd service for node exporter
  template:
    src: node-exporter.service.j2
    dest: /etc/systemd/system/node-exporter.service
  notify:
    - reload systemd
    - start node exporter

- name: Configure Filebeat
  template:
    src: filebeat.yml.j2
    dest: /etc/filebeat/filebeat.yml
  notify: restart filebeat
```

## Troubleshooting Tips

### Debugging Techniques
```bash
# Verbose output
ansible-playbook site.yml -v    # basic verbosity
ansible-playbook site.yml -vv   # more verbose
ansible-playbook site.yml -vvv  # connection debugging
ansible-playbook site.yml -vvvv # enable connection debugging

# Check mode (dry run)
ansible-playbook site.yml --check

# Show differences
ansible-playbook site.yml --diff

# Debug module
- name: Debug variable
  debug:
    var: my_variable

- name: Debug message
  debug:
    msg: "Variable value is {{ my_variable }}"

# Conditional debugging
- name: Debug when condition is true
  debug:
    msg: "This host is a web server"
  when: "'webservers' in group_names"

# Pause playbook
- name: Pause for manual verification
  pause:
    prompt: "Check the application status, then press enter to continue"

# Step mode
ansible-playbook site.yml --step
```

### Common Issues and Solutions
```yaml
# SSH connection issues
- name: Fix SSH connection
  connection: local
  tasks:
    - name: Add host key
      known_hosts:
        name: "{{ inventory_hostname }}"
        key: "{{ lookup('pipe', 'ssh-keyscan ' + inventory_hostname) }}"

# Permission issues
- name: Ensure correct ownership
  file:
    path: /var/www/html
    owner: www-data
    group: www-data
    recurse: yes
  become: yes

# Service startup issues
- name: Wait for service to start
  wait_for:
    port: 80
    host: "{{ inventory_hostname }}"
    timeout: 60

# Handle errors gracefully
- name: Attempt risky operation
  shell: /path/to/risky/command
  register: result
  failed_when: false
  changed_when: result.rc == 0

- name: Handle failure
  debug:
    msg: "Command failed with return code {{ result.rc }}"
  when: result.rc != 0

# Retry failed tasks
- name: Download file with retry
  get_url:
    url: https://example.com/file.zip
    dest: /tmp/file.zip
  retries: 3
  delay: 5
  register: result
  until: result is succeeded
```

### Performance Optimization
```yaml
# Use strategies for better performance
- name: Optimize playbook execution
  hosts: all
  strategy: free  # Don't wait for all hosts to complete each task
  
  tasks:
    - name: Gather facts only when needed
      setup:
      when: ansible_facts is not defined

# Parallel execution
- name: Run tasks in parallel
  shell: "{{ item }}"
  loop:
    - command1
    - command2
    - command3
  async: 60
  poll: 0
  register: async_results

- name: Wait for parallel tasks
  async_status:
    jid: "{{ item.ansible_job_id }}"
  loop: "{{ async_results.results }}"
  register: async_status
  until: async_status.finished
  retries: 30
  delay: 2

# Efficient loops
- name: Install packages efficiently
  package:
    name: "{{ packages }}"
    state: present
  # Instead of looping over individual packages

# Cache facts
gather_facts: yes
fact_caching: jsonfile
fact_caching_connection: /tmp/ansible_facts_cache
fact_caching_timeout: 86400
```

## Official Documentation Links

- [Ansible Documentation](https://docs.ansible.com/)
- [Ansible Galaxy](https://galaxy.ansible.com/)
- [Ansible Modules Index](https://docs.ansible.com/ansible/latest/collections/index_module.html)
- [Ansible Best Practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)
- [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html)
- [Ansible Configuration](https://docs.ansible.com/ansible/latest/reference_appendices/config.html)
- [Jinja2 Templates](https://jinja.palletsprojects.com/templates/)
- [YAML Syntax](https://docs.ansible.com/ansible/latest/reference_appendices/YAMLSyntax.html)
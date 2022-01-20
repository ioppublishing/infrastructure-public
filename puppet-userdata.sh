#!/bin/bash
set -euo pipefail

# To include this script in userdata:
# From an AWS EC2 host:
# curl --retry 3 https://raw.githubusercontent.com/ioppublishing/infrastructure-public/master/puppet-userdata.sh?$(date +%s) | /bin/bash -s
#
# From a non-AWS host:
# wget https://raw.githubusercontent.com/ioppublishing/infrastructure-public/master/puppet-userdata.sh?$(date +%s) -O /tmp/puppet-userdata.sh
# sh /tmp/userdata.sh -s fqdn puppet_role puppet_env ocm_server ocm_region
# Eg
# sh /tmp/userdata.sh myhostname.mydomain.com myrole stage opsworks-puppetmaster-name eu-west-1

# If there are problems on an AWS EC2 host:
# to create a debugging log in /var/log/pu.log, edit the userdata to be as follows:
# curl --retry 3 https://raw.githubusercontent.com/ioppublishing/infrastructure-public/master/puppet-userdata.sh?$(date +%s) | /bin/bash -sx 2>&1 | tee -a /var/log/pu.log

# To (re-)run on a node that has already had Puppet configured, first run "yum remove puppet-agent"

# EC2 Inputs (Tags):
# Env        (EC2 tag, required) - The Puppet environment to use (e.g. stage)
# Role       (EC2 tag, required) - The puppet role to use (e.g. svc)
# Name       (EC2 tag, required) - Used as the Puppet node / certificate name and 'realhostname' fact.  Should be unique, ideally a FQDN.
# ocm_server (EC2 tag, optional) - The Opsworks Puppetmaster Name to connect to (default: nonprodpuppet)
# ocm_region (EC2 tag, optional) - The AWS region the Opsworks Puppetmaster is in (default: eu-west-1)

if [ $# -eq 0 ]; then
    args_mode="aws"
elif [ $# -eq 5 ]; then
    args_mode="non-aws"
    arg_fqdn=$1
    arg_puppet_role=$2
    arg_puppet_environment=$3
    arg_ocm_server=$4
    arg_ocm_region=$5
else
    echo "Error: Unknown arguments"
    echo "For AWS EC2, run with no arguments"
    echo "For other systems;"
    echo "  sh /tmp/puppet-userdata.sh fqdn puppet_role puppet_env ocm_server ocm_region"
    echo "  Eg:"
    echo "  sh /tmp/puppet-userdata.sh myhostname.mydomain.com myrole stage opsworks-puppetmaster-name eu-west-1"
    exit 1
fi

function prepareforaws {
    yum install -y epel-release
    yum install -y awscli
    yum install -y python3-pip
    if [ $args_mode == "aws" ]; then
        REGION=$(curl --silent --show-error --retry 3 http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//')
        INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)
        CURRENT_TAG=$(/bin/aws ec2 describe-tags --region ${REGION} --filters Name=resource-id,Values=${INSTANCE_ID} Name=key,Values=Name --query Tags[].Value --output text)
        ASG_TAG=$(/bin/aws ec2 describe-tags --region ${REGION} --filters Name=resource-id,Values=${INSTANCE_ID} Name=key,Values=aws:autoscaling:groupName --query Tags[].Value --output text)
        if [[ ${ASG_TAG} != "" ]]; then
          if [[ ${CURRENT_TAG} != *${INSTANCE_ID}* ]]; then
              aws ec2 create-tags --region ${REGION} --resources ${INSTANCE_ID} --tags Key=Name,Value=${CURRENT_TAG}_${INSTANCE_ID}
          fi
        fi
        pip3 install https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-py3-latest.tar.gz
    fi
}

function get_AWS_config() {
    #set aws settings
    export EC2_TOKEN=$(curl --silent --show-error --retry 3 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
    export PP_INSTANCE_ID=$(curl --silent --show-error --retry 3 -H "X-aws-ec2-metadata-token: $EC2_TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
    # this uses the EC2 instance ID as the node name
    export PP_IMAGE_NAME=$(curl --silent --show-error --retry 3 -H "X-aws-ec2-metadata-token: $EC2_TOKEN" http://169.254.169.254/latest/meta-data/ami-id)
    export PP_REGION=$(curl --silent --show-error --retry 3 -H "X-aws-ec2-metadata-token: $EC2_TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//')

    export PP_INSTANCE_ID_EXTENSION='1.3.6.1.4.1.34380.1.1.2'
    export PP_REGION_EXTENSION='1.3.6.1.4.1.34380.1.1.18'
    export PP_IMAGE_NAME_EXTENSION='1.3.6.1.4.1.34380.1.1.3'

    # NB: Where a second argument is passed to get_ec2_tag, it is the default value if the tag is not found or is blank.

    export ocm_server=$(get_ec2_tag ocm_server nonprodpuppet)
    export ocm_region=$(get_ec2_tag ocm_region eu-west-1)
    export puppet_role=$(get_ec2_tag Role)
    export puppet_environment=$(get_ec2_tag Env)
    export fqdn=$(get_ec2_tag Name)
}

function get_NonAWS_config() {
    export PP_INSTANCE_ID=
    export PP_IMAGE_NAME=
    export PP_REGION=$arg_ocm_region

    export ocm_server=$arg_ocm_server
    export ocm_region=$arg_ocm_region
    export puppet_role=$arg_puppet_role
    export puppet_environment=$arg_puppet_environment
    export fqdn=$arg_fqdn
}

function get_global_config() {
    export PUPPETSERVER=$(/bin/aws opsworks-cm describe-servers --region=$ocm_region --query "Servers[?ServerName=='$ocm_server'].Endpoint" --output text)
    export PRUBY='/opt/puppetlabs/puppet/bin/ruby'
    export PUPPET='/opt/puppetlabs/bin/puppet'
    export DAEMONSPLAY='true'
    export SPLAYLIMIT='30'
    export PUPPET_CA_PATH='/etc/puppetlabs/puppet/ssl/certs/ca.pem'
}

function display_config() {
    echo "Using fqdn               = ${fqdn}"
    echo "Using puppet_role        = ${puppet_role}"
    echo "Using puppet_environment = ${puppet_environment}"
    echo "Using ocm_server         = ${ocm_server}"
    echo "Using ocm_region         = ${ocm_region}"
    echo "Using PUPPETSERVER       = ${PUPPETSERVER}"
    echo "Using PP_INSTANCE_ID     = ${PP_INSTANCE_ID}"
    echo "Using PP_IMAGE_NAME      = ${PP_IMAGE_NAME}"
    echo "Using PP_REGION          = ${PP_REGION}"
}

function get_config() {
    if [ $args_mode == "aws" ]; then
        echo Using AWS settings ...
        get_AWS_config
    else
        echo Using non-AWS settings ...
        get_NonAWS_config
    fi
    get_global_config
    display_config
}

function get_ec2_tag() {
    local tag_name=${1}
    local default_value=${2:-}

    local tag_value=$(/bin/aws ec2 describe-tags \
        --region ${PP_REGION} \
        --filters "Name=resource-id,Values=${PP_INSTANCE_ID}" \
        --query "Tags[?Key==\`${tag_name}\`].Value" \
        --output text)

    if [[ $? = 0 ]] && [[ ! -z ${tag_value}  ]]; then
        echo ${tag_value}
    elif [[ ! -z ${default_value} ]]; then
        echo ${default_value}
    else
        >&2 echo "ERROR: could not find required EC2 tag '${tag_name}'"
        exit 1
    fi
}

function loadmodel {
    curl --silent --show-error --retry 3 https://s3.amazonaws.com/opsworks-cm-us-east-1-prod-default-assets/misc/owpe/model-2017-09-05/opsworkscm-2016-11-01.normal.json -o /root/opsworkscm-2016-11-01.normal.json
    /bin/aws configure add-model --service-model file:///root/opsworkscm-2016-11-01.normal.json --service-name opsworks-cm-puppet
}

function preparepuppet {
    mkdir -p /opt/puppetlabs/puppet/cache/state
    mkdir -p /etc/puppetlabs/puppet/ssl/certs/
    mkdir -p /etc/puppetlabs/code/modules/

    mkdir -p /etc/puppetlabs/facter/facts.d
    echo "role: ${puppet_role:?}" > /etc/puppetlabs/facter/facts.d/role.yaml
    echo "realhostname: ${fqdn:?}" > /etc/puppetlabs/facter/facts.d/realhostname.yaml

    echo "{"disabled_message":"Locked by OpsWorks Deploy - $(date --iso-8601=seconds)"}" > /opt/puppetlabs/puppet/cache/state/agent_disabled.lock
}

function establishtrust {
    /bin/aws opsworks-cm describe-servers --region=$ocm_region --server-name $ocm_server --query "Servers[0].EngineAttributes[?Name=='PUPPET_API_CA_CERT'].Value" --output text > /etc/puppetlabs/puppet/ssl/certs/ca.pem

    /bin/aws opsworks-cm describe-servers --region=$ocm_region --server-name $ocm_server --query "Servers[0].EngineAttributes[?Name=='PUPPET_API_CRL'].Value" --output text > /etc/puppetlabs/puppet/ssl/crl.pem
    if [ ! -s /etc/puppetlabs/puppet/ssl/crl.pem ] ; then
        rm /etc/puppetlabs/puppet/ssl/crl.pem
    fi
}

function installpuppet {
    ADD_EXTENSIONS=$(generate_csr_attributes)

    curl --retry 3 \
        --cacert /etc/puppetlabs/puppet/ssl/certs/ca.pem \
        "https://$PUPPETSERVER:8140/packages/current/install.bash" \
        | /bin/bash -s \
        agent:certname=${fqdn:?} \
        agent:splay=${DAEMONSPLAY} \
        extension_requests:${PP_INSTANCE_ID_EXTENSION}=${PP_INSTANCE_ID} \
        extension_requests:${PP_REGION_EXTENSION}=${PP_REGION} \
        extension_requests:${PP_IMAGE_NAME_EXTENSION}=${PP_IMAGE_NAME} \
        ${ADD_EXTENSIONS}

        $PUPPET resource service puppet ensure=stopped
}

function generate_csr_attributes {
    pp_tags=$(/bin/aws ec2 describe-tags --region $PP_REGION --filters "Name=resource-id,Values=${PP_INSTANCE_ID}" --query 'Tags[?starts_with(Key, `pp_`)].[Key,Value]' --output text | sed s/\t/=/)

    csr_attrs=""
    for i in $pp_tags
    do
        csr_attrs="$csr_attrs extension_requests:$i"
    done

    echo $csr_attrs
}


function installpuppetbootstrap {
    $PUPPET help bootstrap > /dev/null && bootstrap_installed=true || bootstrap_installed=false
    if [ "$bootstrap_installed" = false ]; then
         echo "Puppet Bootstrap not present, installing"
         curl --retry 3 https://s3.amazonaws.com/opsworks-cm-us-east-1-prod-default-assets/misc/owpe/puppet-agent-bootstrap-0.2.1.tar.gz          -o /tmp/puppet-agent-bootstrap-0.2.1.tar.gz
         $PUPPET module install /tmp/puppet-agent-bootstrap-0.2.1.tar.gz --ignore-dependencies
         echo "Puppet Bootstrap installed"
    else
         echo "Puppet Bootstrap already present"
    fi
}

function associatenode {
    $PUPPET config set environment "${puppet_environment:?}" --section agent
    CERTNAME=$(${PUPPET} config print certname --section agent)
    SSLDIR=$(${PUPPET} config print ssldir --section agent)
    PP_CSR_PATH="${SSLDIR}/certificate_requests/${CERTNAME}.pem"
    PP_CERT_PATH="${SSLDIR}/certs/${CERTNAME}.pem"

    #clear out extraneous certs and generate a new one
    ${PUPPET} bootstrap purge
    ${PUPPET} bootstrap csr
    # submit the cert
    ASSOCIATE_TOKEN=$(/bin/aws opsworks-cm associate-node --region ${ocm_region} --server-name ${ocm_server} --node-name ${CERTNAME} --engine-attributes Name=PUPPET_NODE_CSR,Value="`cat $PP_CSR_PATH`" --query "NodeAssociationStatusToken" --output text)
    #wait
    /bin/aws opsworks-cm wait node-associated --region ${ocm_region} --node-association-status-token "${ASSOCIATE_TOKEN}" --server-name ${ocm_server}
    #install and verify
    /bin/aws opsworks-cm-puppet describe-node-association-status --region ${ocm_region} --node-association-status-token "${ASSOCIATE_TOKEN}" --server-name ${ocm_server} --query 'EngineAttributes[0].Value' --output text > ${PP_CERT_PATH}
    establishtrust
    # ridiculous change to get the CRL
    puppet agent -t --noop || true
    ${PUPPET} bootstrap verify
}

function runpuppet {
    sleep $[ ( $RANDOM % $SPLAYLIMIT ) + 1]s
    cat /proc/sys/net/netfilter/nf_conntrack_helper >> /tmp/nf_conntrack_helper
    cat /etc/sysctl.conf >> /tmp/nf_conntrack_helper_systl.conf
    $PUPPET agent --enable
    $PUPPET agent --onetime --no-daemonize --no-usecacheonfailure --no-splay --debug --show_diff
    $PUPPET resource service puppet ensure=running enable=true
}

# Order of execution of functions
prepareforaws
get_config
loadmodel
preparepuppet
establishtrust
installpuppet
installpuppetbootstrap
associatenode
runpuppet

touch /tmp/userdata.done

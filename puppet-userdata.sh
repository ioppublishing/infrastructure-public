#!/bin/bash
set -euo pipefail

# To include this script in userdata:
# From an AWS EC2 host:
# curl --retry 3 https://raw.githubusercontent.com/ioppublishing/infrastructure-public/master/puppet-userdata.sh?$(date +%s) | /bin/bash -s
#
# From a non-AWS host:
# wget https://raw.githubusercontent.com/ioppublishing/infrastructure-public/master/puppet-userdata.sh?$(date +%s) -o /tmp/puppet-userdata.sh
# sh /tmp/userdata.sh -s fqdn puppet_role puppet_env ocm_server ocm_region
# Eg
# sh /tmp/userdata.sh myhostname.mydomain.com myrole stage opsworks-puppetmaster-name eu-west-1

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
    yum install -y awscli
    export PATH=/usr/local/aws/bin:$PATH
}

function get_AWS_config() {
    # NB: Where a second argument is passed to get_ec2_tag, it is the default value if the tag is not found or is blank.

    export ocm_server=$(get_ec2_tag ocm_server nonprodpuppet)
    export ocm_region=$(get_ec2_tag ocm_region eu-west-1)
    export puppet_role=$(get_ec2_tag Role)
    export puppet_environment=$(get_ec2_tag Env)
    export fqdn=$(get_ec2_tag Name)

    #set aws settings
    export PP_INSTANCE_ID=$(curl --silent --show-error --retry 3 http://169.254.169.254/latest/meta-data/instance-id)
    export PP_IMAGE_NAME=$(curl --silent --show-error --retry 3 http://169.254.169.254/latest/meta-data/ami-id)
    export PP_REGION=$(curl --silent --show-error --retry 3 http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//')
}

function get_NonAWS_config() {
    export ocm_server=$arg_ocm_server
    export ocm_region=$arg_ocm_region
    export puppet_role=$arg_puppet_role
    export puppet_environment=$arg_puppet_environment
    export fqdn=$arg_fqdn
    export PP_INSTANCE_ID=
    export PP_IMAGE_NAME=
    export PP_REGION=$arg_ocm_region
}

function get_global_config() {
    export PUPPETSERVER=$(aws opsworks-cm describe-servers --region=$ocm_region --query "Servers[?ServerName=='$ocm_server'].Endpoint" --output text)
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

    local tag_value=$(aws ec2 describe-tags \
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
    aws configure add-model --service-model https://s3.amazonaws.com/opsworks-cm-us-east-1-prod-default-assets/misc/owpe/model-2017-09-05/opsworkscm-2016-11-01.normal.json --service-name opsworks-cm-puppet
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
    aws opsworks-cm describe-servers --region=$ocm_region --server-name $ocm_server --query "Servers[0].EngineAttributes[?Name=='PUPPET_API_CA_CERT'].Value" --output text > /etc/puppetlabs/puppet/ssl/certs/ca.pem
}

function installpuppet {
    ADD_EXTENSIONS=$(generate_csr_attributes)

    curl --retry 3 \
        --cacert /etc/puppetlabs/puppet/ssl/certs/ca.pem \
        "https://$PUPPETSERVER:8140/packages/current/install.bash" \
        | /bin/bash -s \
        agent:certname=${fqdn:?} \
        agent:splay=${DAEMONSPLAY} \
        extension_requests:pp_instance_id=${PP_INSTANCE_ID} \
        extension_requests:pp_region=${PP_REGION} \
        extension_requests:pp_image_name=${PP_IMAGE_NAME} \
        $ADD_EXTENSIONS

        $PUPPET resource service puppet ensure=stopped
}

function generate_csr_attributes {
    pp_tags=$(aws ec2 describe-tags --region $PP_REGION --filters "Name=resource-id,Values=${PP_INSTANCE_ID}" --query 'Tags[?starts_with(Key, `pp_`)].[Key,Value]' --output text | sed s/\t/=/)

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
    CERTNAME=$($PUPPET config print certname --section agent)
    SSLDIR=$($PUPPET config print ssldir --section agent)
    PP_CSR_PATH="$SSLDIR/certificate_requests/$CERTNAME.pem"
    PP_CERT_PATH="$SSLDIR/certs/$CERTNAME.pem"

    #clear out extraneous certs and generate a new one
    $PUPPET bootstrap purge
    $PUPPET bootstrap csr

    # submit the cert
    ASSOCIATE_TOKEN=$(aws opsworks-cm associate-node --region $ocm_region --server-name $ocm_server --node-name $CERTNAME --engine-attributes Name=PUPPET_NODE_CSR,Value="`cat $PP_CSR_PATH`" --query "NodeAssociationStatusToken" --output text)

    #wait
    aws opsworks-cm wait node-associated --region $ocm_region --node-association-status-token "$ASSOCIATE_TOKEN" --server-name $ocm_server
    #install and verify
    aws opsworks-cm-puppet describe-node-association-status --region $ocm_region --node-association-status-token "$ASSOCIATE_TOKEN" --server-name $ocm_server --query 'EngineAttributes[0].Value' --output text > $PP_CERT_PATH

    $PUPPET bootstrap verify
}

function runpuppet {
    sleep $[ ( $RANDOM % $SPLAYLIMIT ) + 1]s
    $PUPPET agent --enable
    $PUPPET agent --onetime --no-daemonize --no-usecacheonfailure --no-splay --verbose && true
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

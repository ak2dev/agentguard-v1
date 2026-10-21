# Creates the AWS resources for Agent Guard Web in your project's Region and starts the
# instance. Run from Windows PowerShell after `aws login --profile agentguard`:
#   powershell -ExecutionPolicy Bypass -File deploy\aws\launch.ps1
# Creates: an IAM role + instance profile (Session Manager only), a security group
# (HTTP/HTTPS in, nothing else), one t4g.small instance and an Elastic IP.
# Re-running reuses the role, profile and security group; it always launches a new
# instance, so run it once (see README.md for teardown).

param(
    [string] $AwsProfile = 'agentguard',
    [string] $Region = 'ap-southeast-2',
    [string] $Name = 'agentguard-web',
    [string] $InstanceType = 't4g.small'
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

# Windows PowerShell 5.1 turns a native command's stderr into errors, which 'Stop'
# would throw on; check exit codes instead inside these helpers.
function Invoke-Aws {
    $ErrorActionPreference = 'Continue'
    $out = & aws @args --profile $AwsProfile --region $Region --output text 2>&1
    if ($LASTEXITCODE -ne 0) { throw "aws $($args -join ' ') failed: $($out | Out-String)" }
    return ($out | Out-String).Trim()
}

function Test-Aws {
    $ErrorActionPreference = 'Continue'
    & aws @args --profile $AwsProfile --region $Region --output text 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

$role = "$Name-ec2"
Write-Host "== IAM role and instance profile: $role"
if (-not (Test-Aws iam get-role --role-name $role)) {
    Invoke-Aws iam create-role --role-name $role --description 'Agent Guard Web instance: Session Manager access only' `
        --assume-role-policy-document "file://$here\ec2-trust.json" | Out-Null
}
Invoke-Aws iam attach-role-policy --role-name $role --policy-arn 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore' | Out-Null
if (-not (Test-Aws iam get-instance-profile --instance-profile-name $role)) {
    Invoke-Aws iam create-instance-profile --instance-profile-name $role | Out-Null
    Invoke-Aws iam add-role-to-instance-profile --instance-profile-name $role --role-name $role | Out-Null
    Write-Host 'waiting for the instance profile to propagate...'
    Start-Sleep -Seconds 15
}

Write-Host '== security group (80/443 from anywhere, no SSH)'
$vpc = Invoke-Aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId'
if (-not $vpc -or $vpc -eq 'None') { throw 'no default VPC in this Region' }
$sg = Invoke-Aws ec2 describe-security-groups --filters "Name=group-name,Values=$Name" "Name=vpc-id,Values=$vpc" --query 'SecurityGroups[0].GroupId'
if (-not $sg -or $sg -eq 'None') {
    $sg = Invoke-Aws ec2 create-security-group --group-name $Name --description 'Agent Guard Web: HTTP and HTTPS only' --vpc-id $vpc --query GroupId
    foreach ($port in 80, 443) {
        Invoke-Aws ec2 authorize-security-group-ingress --group-id $sg `
            --ip-permissions "IpProtocol=tcp,FromPort=$port,ToPort=$port,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}]" | Out-Null
    }
}
Write-Host "security group: $sg"

Write-Host "== launching $InstanceType (Amazon Linux 2023, arm64)"
$instance = Invoke-Aws ec2 run-instances `
    --image-id 'resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64' `
    --instance-type $InstanceType `
    --iam-instance-profile "Name=$role" `
    --security-group-ids $sg `
    --user-data "file://$here\bootstrap.sh" `
    --metadata-options 'HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled' `
    --credit-specification 'CpuCredits=standard' `
    --block-device-mappings "file://$here\block-devices.json" `
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$Name}]" "ResourceType=volume,Tags=[{Key=Name,Value=$Name}]" `
    --query 'Instances[0].InstanceId'
Write-Host "instance: $instance"
Invoke-Aws ec2 wait instance-running --instance-ids $instance | Out-Null

Write-Host '== Elastic IP'
$alloc = Invoke-Aws ec2 allocate-address --domain vpc --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=$Name}]" --query AllocationId
Invoke-Aws ec2 associate-address --instance-id $instance --allocation-id $alloc | Out-Null
$ip = Invoke-Aws ec2 describe-addresses --allocation-ids $alloc --query 'Addresses[0].PublicIp'

$domain = ($ip -replace '\.', '-') + '.sslip.io'
Write-Host ''
Write-Host "Instance:   $instance"
Write-Host "Elastic IP: $ip  ($alloc)"
Write-Host "Default domain: $domain"
Write-Host ''
Write-Host 'Next: wait ~5 minutes for bootstrap, then connect with Session Manager:'
Write-Host "  https://$Region.console.aws.amazon.com/ec2/home?region=$Region#ConnectToInstance:instanceId=$instance"
Write-Host 'and run:  sudo bash /opt/agentguard/deploy/aws/deploy.sh'

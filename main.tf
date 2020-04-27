provider "aws" {
    region = "ap-northeast-1"
}

module "describe_regions_for_ec2"{
    source = "./iam_role"
    name = "describe_regions_for_ec2"
    identifier = "ec2.amazonaws.com"
    policy = data.aws_iam_policy_document.allow_describe_regions.json

}

data "aws_iam_policy_document" "allow_describe_regions" {
  statement {
    effect    = "Allow"
    actions   = ["ec2:DescribeRegions"] # リージョン一覧を取得する
    resources = ["*"]
  }
}

resource "aws_s3_bucket" "private" {
    bucket = "private-bucket-kotarosz727"

    versioning {
        enabled = true
    }

    server_side_encryption_configuration {
        rule {
            apply_server_side_encryption_by_default {
                sse_algorithm = "AES256"
            }
        }
    }
}

resource "aws_s3_bucket_public_access_block" "private" {
    bucket = aws_s3_bucket.private.id
    block_public_acls = true
    block_public_policy = true
    ignore_public_acls = true
    restrict_public_buckets = true
}

resource "aws_s3_bucket" "public" {
    bucket = "public-pragmatic-kotarosz727"
    acl = "public-read"

    cors_rule {
        allowed_origins = ["https//example.com"]
        allowed_methods = ["GET"]
        allowed_headers = ["*"]
        max_age_seconds = 3000
    }
}

resource "aws_s3_bucket" "alb_log" {
    bucket = "alb-log-pragmatic-kotarsz727"

    lifecycle_rule{
        enabled = true

        expiration{
            days = "180"
        }
    }
}

resource "aws_s3_bucket_policy" "alb_log" {
    bucket = aws_s3_bucket.alb_log.id
    policy = data.aws_iam_policy_document.alb_log.json
}

data "aws_iam_policy_document" "alb_log" {
    statement {
        effect = "Allow"
        actions = ["s3:PutObject"]
        resources = ["arn:aws:s3:::${aws_s3_bucket.alb_log.id}/*"]

        principals {
            type = "AWS"
            identifiers = ["582318560864"]
        }
    }
}

resource "aws_s3_bucket" "force_destroy" {
    bucket = "force-destroy-pragmatic-terraform-suzuki"
    force_destroy = true
}

resource "aws_vpc" "example" {
    cidr_block = "10.0.0.0/16"
    enable_dns_support = true
    enable_dns_hostnames = true

    tags = {
        Name = "example_terraform"
    }
}

resource "aws_subnet" "public_0" {
    vpc_id = aws_vpc.example.id
    cidr_block = "10.0.1.0/24"
    map_public_ip_on_launch = true
    availability_zone = "ap-northeast-1d"
}

resource "aws_subnet" "public_1" {
    vpc_id = aws_vpc.example.id
    cidr_block = "10.0.2.0/24"
    map_public_ip_on_launch = true
    availability_zone = "ap-northeast-1c"
}

resource "aws_internet_gateway" "example" {
    vpc_id = aws_vpc.example.id
}

resource "aws_route_table" "public" {
    vpc_id = aws_vpc.example.id
}

resource "aws_route" "public" {
    route_table_id = aws_route_table.public.id
    gateway_id = aws_internet_gateway.example.id
    destination_cidr_block = "0.0.0.0/0"
}

resource "aws_route_table_association" "public_0" {
    subnet_id = aws_subnet.public_0.id
    route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_1" {
    subnet_id = aws_subnet.public_1.id
    route_table_id = aws_route_table.public.id
}

resource "aws_subnet" "private_0" {
    vpc_id = aws_vpc.example.id
    cidr_block = "10.0.65.0/24"
    availability_zone = "ap-northeast-1a"
    map_public_ip_on_launch = false
}

resource "aws_subnet" "private_1" {
    vpc_id = aws_vpc.example.id
    cidr_block = "10.0.66.0/24"
    availability_zone = "ap-northeast-1c"
    map_public_ip_on_launch = false
}

resource "aws_route_table" "private_0" {
    vpc_id = aws_vpc.example.id
}

resource "aws_route_table" "private_1" {
    vpc_id = aws_vpc.example.id
}

resource "aws_route_table_association" "private_0" {
    subnet_id = aws_subnet.private_0.id
    route_table_id = aws_route_table.private_0.id
}

resource "aws_route_table_association" "private_1" {
    subnet_id = aws_subnet.private_1.id
    route_table_id = aws_route_table.private_1.id
}

resource "aws_eip" "nat_gateway_0" {
    vpc = true
    depends_on = [aws_internet_gateway.example]
}

resource "aws_eip" "nat_gateway_1" {
    vpc = true
    depends_on = [aws_internet_gateway.example]
}

resource "aws_nat_gateway" "nat_gateway_0" {
    allocation_id = aws_eip.nat_gateway_0.id
    subnet_id = aws_subnet.public_0.id
    depends_on = [aws_internet_gateway.example]
}

resource "aws_nat_gateway" "nat_gateway_1" {
    allocation_id = aws_eip.nat_gateway_1.id
    subnet_id = aws_subnet.public_1.id
    depends_on = [aws_internet_gateway.example]
}

resource "aws_route" "private_0" {
    route_table_id = aws_route_table.private_0.id
    nat_gateway_id = aws_nat_gateway.nat_gateway_0.id
    destination_cidr_block = "0.0.0.0/0"
}

resource "aws_route" "private_1" {
    route_table_id = aws_route_table.private_1.id
    nat_gateway_id = aws_nat_gateway.nat_gateway_1.id
    destination_cidr_block = "0.0.0.0/0"
}

module "example_sg" {
    source = "./security_group"
    name = "module-sg"
    vpc_id = aws_vpc.example.id
    port = 80
    cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_lb" "example" {
    name = "example"
    load_balancer_type = "application"
    internal = false
    idle_timeout = 60

    subnets = [
        aws_subnet.public_0.id,
        aws_subnet.public_1.id,
    ]

    access_logs {
        bucket = aws_s3_bucket.alb_log.id
        enabled = true
    }

    security_groups = [
        module.http_sg.security_group_id,
        module.https_sg.security_group_id,
        module.http_redirect_sg.security_group_id,
    ]
}

output "alb_dns_name" {
    value = aws_lb.example.dns_name
}

module "http_sg" {
    source = "./security_group"
    name = "http-sg"
    vpc_id = aws_vpc.example.id
    port = 80
    cidr_blocks = ["0.0.0.0/0"]
}

module "https_sg" {
    source = "./security_group"
    name = "https-sg"
    vpc_id = aws_vpc.example.id
    port = 443
    cidr_blocks = ["0.0.0.0/0"]
}

module "http_redirect_sg" {
    source = "./security_group"
    name = "http_redirect_sg"
    vpc_id = aws_vpc.example.id
    port = 8080
    cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_lb_listener" "http" {
    load_balancer_arn = aws_lb.example.arn
    port = "80"
    protocol = "HTTP"

    default_action{
        type = "fixed-response"
    
        fixed_response{
            content_type = "text/plain"
            message_body = "これは「http」です"
            status_code = "200"
        }
    }    
}

data "aws_route53_zone" "example" {
    name = "abcd1234szk.ml."
}

resource "aws_route53_record" "example" {
    zone_id = data.aws_route53_zone.example.zone_id
    name = data.aws_route53_zone.example.name
    type = "A"

    alias {
        name = aws_lb.example.dns_name
        zone_id = aws_lb.example.zone_id
        evaluate_target_health = true
    }
}

output "domain_name" {
    value = aws_route53_record.example.name
}

resource "aws_acm_certificate" "example" {
    domain_name = aws_route53_record.example.name
    subject_alternative_names = []
    validation_method = "DNS"

    lifecycle {
        create_before_destroy = true
    }
}

resource "aws_route53_record" "example_certificate" {
    name = aws_acm_certificate.example.domain_validation_options[0].resource_record_name
    type = aws_acm_certificate.example.domain_validation_options[0].resource_record_type
    records = [
        aws_acm_certificate.example.domain_validation_options[0].resource_record_value
    ]
    zone_id = data.aws_route53_zone.example.id
    ttl = 60
}

resource "aws_acm_certificate_validation" "example" {
    certificate_arn = aws_acm_certificate.example.arn
    validation_record_fqdns = [aws_route53_record.example_certificate.fqdn]
}

//HTTPS用ロードバランサー
resource "aws_lb_listener" "https" {
    load_balancer_arn = aws_lb.example.arn
    port = "443"
    protocol = "HTTPS"
    certificate_arn = aws_acm_certificate.example.arn
    //推奨ポリシー
    ssl_policy = "ELBSecurityPolicy-2016-08"

    default_action {
        type = "fixed-response"

        fixed_response {
            content_type = "text/plain"
            message_body = "これはHTTPSです"
            status_code = 200
        }
    }
}

//HTTPのリダイレクト
resource "aws_lb_listener" "redirect_http_to_https" {
    load_balancer_arn = aws_lb.example.arn
    port = "8080"
    protocol = "HTTP"

    default_action {
        type = "redirect"

        redirect {
            port = "443"
            protocol = "HTTPS"
            status_code = "HTTP_301"
        }
    }
}

//ターゲットグループ
resource "aws_lb_target_group" "example" {
    name = "example"
    target_type = "ip"
    vpc_id = aws_vpc.example.id
    port = 80
    protocol = "HTTP"
    deregistration_delay = 300

    health_check {
        path = "/"
        healthy_threshold = 5
        unhealthy_threshold = 2
        timeout = 5
        interval = 30
        matcher = 200
        port = "traffic-port"
        protocol = "HTTP"
    }
    //依存関係を制御
    depends_on = [aws_lb.example]
}

//リスナールール
resource "aws_lb_listener_rule" "example" {
    listener_arn = aws_lb_listener.https.arn
    priority = 100

    action {
        type = "forward"
        target_group_arn = aws_lb_target_group.example.arn
    }

    condition {
        field = "path-pattern"
        values = ["/*"]
    }
}

//ECSクラスタの定義
resource "aws_ecs_cluster" "example" {
    name = "example"
}

//タスク（コンテナの実行単位）定義
resource "aws_ecs_task_definition" "example" {
    family = "example"
    cpu = "256"
    memory = "512"
    network_mode = "awsvpc"
    requires_compatibilities = ["FARGATE"]
    container_definitions = file("./container_definitions.json")
}

//ECSサービスの定義
resource "aws_ecs_service" "example" {
    name = "example"
    cluster = aws_ecs_cluster.example.arn
    task_definition = aws_ecs_task_definition.example.arn
    //ESCが維持するタスク数
    desired_count = 2
    launch_type = "FARGATE"
    platform_version = "1.3.0"
    health_check_grace_period_seconds = 60
    network_configuration {
        assign_public_ip = false
        security_groups = [module.nginx_sg.security_group_id]

        subnets = [
            aws_subnet.private_0.id,
            aws_subnet.private_1.id,
        ]
    }

    load_balancer {
        target_group_arn = aws_lb_target_group.example.arn
        container_name = "example"
        container_port = 80
    }

    lifecycle {
        ignore_changes = [task_definition]
    }
}

module "nginx_sg" {
    source = "./security_group"
    name = "nginx_sg"
    vpc_id = aws_vpc.example.id
    port = 80
    cidr_blocks = [aws_vpc.example.cidr_block]
}

# resource "aws_db_parameter_group" "example" {
#     name = "example"
#     family = "mysql5.7"
# }































 
  




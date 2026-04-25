terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "eu-central-1"
}

variable "name" {
  type    = string
  default = "aegis-bootstrap"
}

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = list(string)
}

variable "task_subnet_ids" {
  type = list(string)
}

variable "image" {
  type    = string
  default = "ghcr.io/moolen/aegis:bootstrap"
}

variable "config_file_system_id" {
  type = string
}

variable "enable_proxy_protocol_v2" {
  type    = bool
  default = false
}

resource "aws_ecs_cluster" "this" {
  name = var.name
}

resource "aws_security_group" "service" {
  name        = "${var.name}-sg"
  description = "Aegis bootstrap service security group"
  vpc_id      = var.vpc_id

  ingress {
    description = "Proxy traffic"
    from_port   = 3128
    to_port     = 3128
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Metrics traffic"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "this" {
  name               = substr(replace(var.name, "/[^a-zA-Z0-9-]/", "-"), 0, 32)
  load_balancer_type = "network"
  subnets            = var.public_subnet_ids
}

resource "aws_lb_target_group" "proxy" {
  name        = substr("${var.name}-proxy", 0, 32)
  port        = 3128
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = var.vpc_id
  proxy_protocol_v2 = var.enable_proxy_protocol_v2

  health_check {
    port     = "9090"
    protocol = "HTTP"
    path     = "/healthz"
  }
}

resource "aws_lb_listener" "proxy" {
  load_balancer_arn = aws_lb.this.arn
  port              = 3128
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.proxy.arn
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = "arn:aws:iam::123456789012:role/aegisTaskExecutionRole"
  task_role_arn            = "arn:aws:iam::123456789012:role/aegisTaskRole"

  volume {
    name = "config"

    efs_volume_configuration {
      file_system_id = var.config_file_system_id
      root_directory = "/aegis"
    }
  }

  container_definitions = jsonencode([
    {
      name      = "aegis"
      image     = var.image
      essential = true
      command   = ["-config", "/etc/aegis/aegis.yaml"]
      portMappings = [
        {
          containerPort = 3128
          hostPort      = 3128
          protocol      = "tcp"
        },
        {
          containerPort = 9090
          hostPort      = 9090
          protocol      = "tcp"
        }
      ]
      mountPoints = [
        {
          sourceVolume  = "config"
          containerPath = "/etc/aegis"
          readOnly      = true
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = "/ecs/${var.name}"
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    assign_public_ip = false
    subnets          = var.task_subnet_ids
    security_groups  = [aws_security_group.service.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.proxy.arn
    container_name   = "aegis"
    container_port   = 3128
  }
}

output "load_balancer_dns_name" {
  value = aws_lb.this.dns_name
}

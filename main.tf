provider "aws" {
  region  = "ap-south-1"
  profile = "Abhi"
}

resource "tls_private_key" "Abhikey"{
  algorithm = "RSA"
}
resource "aws_key_pair" "Abhikey" {
  key_name   = "Abhi_key"
  public_key =  tls_private_key.Abhikey.public_key_openssh
}


resource "aws_security_group" "abhitf_sg" {
  name        = "Abhi_sg"
  description = "port 22 and port 80"
  vpc_id      = "vpc-c8879aa0"

  ingress {
    description = "ssh, port 22"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

    ingress {
    description = "http, port 80"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_ssh_webserver"
  }
}


resource "aws_instance" "AbhiOs1" {
  ami           = "ami-0732b62d310b80e97"
  instance_type = "t2.micro"
  key_name = "Abhi_key"
  security_groups = [aws_security_group.abhitf_sg.name]

    connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.Abhikey.private_key_pem
    host     = aws_instance.AbhiOs1.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
      "sudo yum install httpd php git -y"
    ]
  }
  tags = {
    Name = "AbhiOs1"
  }
}

resource "aws_efs_file_system" "efs_plus" {
  depends_on = [aws_security_group.abhitf_sg, aws_instance.AbhiOs1]
  creation_token = "efs"

  tags = {
    Name = "abhiefs"
  }
}

resource "aws_efs_mount_target" "mount_efs" {
  depends_on = [aws_efs_file_system.efs_plus]
  file_system_id   = aws_efs_file_system.efs_plus.id
  subnet_id = aws_instance.AbhiOs1.subnet_id
  security_groups=[aws_security_group.abhitf_sg.id]
}

resource "null_resource" "cluster" {
  depends_on = [
    aws_efs_file_system.efs_plus,
  ]

    connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.Abhikey.private_key_pem
    host     = aws_instance.AbhiOs1.public_ip
  }

    provisioner "remote-exec" {
    inline = [
      "sudo echo ${aws_efs_file_system.efs_plus.dns_name}:/var/www/html efs defaults._netdev 0 0>>sudo /etc/fstab",
      "sudo mount ${aws_efs_file_system.efs_plus.dns_name}:/var/www/html/*",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/a1-s2/Hybrid_Multi_Cloud_Task2.git /var/www/html "
    ]
    }
}

resource "aws_s3_bucket" "abhibucket" {
  bucket = "abhibucket13"
  acl    = "public-read"
  force_destroy = true
    tags = {
    Name = "abhibucket"
  }
}

resource "aws_s3_bucket_object" "abhitf_image" {
  depends_on = [
      aws_s3_bucket.abhibucket,
  ]
  key        = "abhiimage"
  bucket     = "abhibucket13"
  content_type = "image/jpg"
  source     = "C:/Users/abc/Desktop/Abhi.png"
  acl = "public-read"
}

resource "aws_cloudfront_origin_access_identity" "abhicf" {
  comment = "cloud_front"
}

locals{
    s3_origin_id = "aws_s3_bucket.abhibucket.id"
}

resource "aws_cloudfront_distribution" "cf_abhi" {
  origin {
    domain_name = aws_s3_bucket.abhibucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "${aws_cloudfront_origin_access_identity.abhicf.cloudfront_access_identity_path}"
    }
  }
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "myimage"

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.abhibucket.bucket_domain_name
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers = ["ORIGIN"]
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress = true
  }

  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

      forwarded_values {
      query_string = false
      headers = ["ORIGIN"]
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress = true
  }

 price_class= "PriceClass_200"
 restrictions {
     geo_restriction {
         restriction_type = "none"
     }
 }

 viewer_certificate{
     cloudfront_default_certificate = true
 }
}

resource "null_resource" "null" {
  depends_on = [
    aws_cloudfront_distribution.cf_abhi,
  ]

    connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.Abhikey.private_key_pem
    host     = aws_instance.AbhiOs1.public_ip
  }

    provisioner "remote-exec" {
    inline = [
      "sudo su << EOF",
      "echo \"<img src='http://${aws_cloudfront_distribution.cf_abhi.domain_name}/${aws_s3_bucket_object.abhitf_image.key}' height='500' width='500'>\" >> /var/www/html/index.html",
      "EOF",
      "sudo systemctl restart httpd",
    ]
    }
}

data "aws_iam_policy_document" "abhis3_policy" {
  statement {
    actions = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.abhibucket.arn}/*"]

  principals {
    type = "AWS"
    identifiers = [aws_cloudfront_origin_access_identity.abhicf.iam_arn]
  }
}
statement {
    actions = [
      "s3:ListBucket",
    ]
    resources = [aws_s3_bucket.abhibucket.arn]

    principals {
    type = "AWS"
    identifiers = [aws_cloudfront_origin_access_identity.abhicf.iam_arn]
    }
}
}

  resource "aws_s3_bucket_policy" "abhibucket_policy" {
  bucket = aws_s3_bucket.abhibucket.id
  policy = data.aws_iam_policy_document.abhis3_policy.json
  }

output "AbhiOs_Ip" {
    value = aws_instance.AbhiOs1.public_ip
}

output "domain_name" {
    value = aws_cloudfront_distribution.cf_abhi.domain_name
}







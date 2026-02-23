output "vpc_id" {
  value = aws_vpc.this.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "public_subnet_b_id" {
  description = "Second public subnet ID (different AZ)"
  value       = aws_subnet.public_b.id
}

output "public_subnet_ids" {
  description = "Both public subnet IDs in a list (for ALB)"
  value       = [aws_subnet.public.id, aws_subnet.public_b.id]
}

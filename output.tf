#####################################
## Virtual Machine Module - Output ##
#####################################

output "vm_windows_server_instance_name" {
  value = var.windows_instance_name
}

output "vm_windows_server_instance_id" {
  value = aws_instance.windows-server.id
}

output "vm_windows_server_instance_public_dns" {
  value = aws_instance.windows-server.public_dns
}

output "vm_windows_server_instance_private_ip" {
  value = aws_instance.windows-server.private_ip
}

output "private_key" {
  value     = nonsensitive(tls_private_key.example.private_key_pem)
  #sensitive = false
}

# Projeto de serviço de autenticação e autorização de usuários

- O objetivo é: uma API rest, com endpoints:
  - Login
  - Login with email
  - Register
  - Authentication

- Onde ao fazer login retorna-se ao cliente um Jwt token.

## Executar localmente

- na raíz há um docker compose, para subir o banco, basta executar o container.

  ```bash
  docker compose up -d
  ```

  ```bash
  docker ps
  ```

- inserindo secrets (variáveis de ambiente sensíveis), o valor "0xa3fa6d97AaAa7e145b37451fc344e58c" é um exemplo
  
  ```bash
  dotnet user-secrets set "SymmetricSecurityKey" "0xa3fa6d97AaAa7e145b37451fc344e58c"
  dotnet user-secrets set "ConnectionStrings:UserConnection" "Host=localhost;Database=prontu_db;Username=teste;Password=teste"
  ```

- executar projeto

  ```bash
  dotnet run --environment "Development"
  ```

  - <http://localhost:5000/swagger>
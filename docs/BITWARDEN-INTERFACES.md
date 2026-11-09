# Interfaces Bitwarden: viabilidade de importar passkeys reais

Pesquisa de Fase 1 em 2026-11-09. Somente documentação pública e leitura de código oficial; nenhum cofre, conta ou credencial do usuário foi acessado. Não houve implementação nem teste autenticado. **Confirmado** significa documentação explícita ou comportamento verificável no código fixado; **inferência** é conclusão de integração; **desconhecido** exige validação adicional.

## Conclusão

**Confirmado:** há transporte de material privado real por JSON e pela resposta de itens da CLI oficial. `login.fido2Credentials[].keyValue` não é apenas metadado: o cliente o importa como chave privada PKCS#8. Portanto, uma importação Linux é tecnicamente plausível sem inventar endpoint ou OAuth. **Inferência:** o caminho inicial de menor dependência é importar JSON explicitamente exportado pelo usuário; uma integração posterior pode executar a CLI oficial com sessão desbloqueada. Isso não comprova compatibilidade do autenticador local nem fornece sincronização bidirecional pronta.

## Fontes fixadas e reprodução da evidência

Código `bitwarden/clients` examinado no commit [`15b835e1efc9e0903cd52f901f57cbae197a403f`](https://github.com/bitwarden/clients/tree/15b835e1efc9e0903cd52f901f57cbae197a403f), obtido do HEAD público. Código `bitwarden/sdk-internal` no commit [`839c6ca06110a7c1fde14fda086dcac096a8d675`](https://github.com/bitwarden/sdk-internal/tree/839c6ca06110a7c1fde14fda086dcac096a8d675). HEAD não é promessa de versão distribuída: a integração deverá fixar e verificar uma versão publicada da CLI antes de produzir compatibilidade suportada.

| Evidência | Caminho oficial fixado |
| --- | --- |
| CLI lista objetos descriptografados e serializa `CipherResponse` | [`apps/cli/src/commands/list.command.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/commands/list.command.ts) |
| Resposta de item constrói `LoginResponse` | [`apps/cli/src/vault/models/cipher.response.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/vault/models/cipher.response.ts) |
| `LoginResponse` herda `LoginExport`; restrição de visualização redige senha/TOTP | [`apps/cli/src/models/response/login.response.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/models/response/login.response.ts) |
| `LoginExport` copia o vetor de passkeys | [`libs/common/src/models/export/login.export.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/models/export/login.export.ts) |
| Serialização inclui `keyValue` e os demais campos abaixo | [`libs/common/src/models/export/fido2-credential.export.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/models/export/fido2-credential.export.ts) |
| JSON individual constrói `CipherWithIdExport`; remove chave de item, preserva login | [`individual-vault-export.service.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/tools/export-vault-core/src/services/individual-vault-export.service.ts) e [`cipher.export.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/models/export/cipher.export.ts) |

### Formato efetivo

**Confirmado no código:** tanto o exportador JSON quanto a cadeia de resposta de `bw list items` preservam `keyValue`. O envelope é diferente: exportação contém `items[]`; listagem retorna uma lista de itens. A remoção de `CipherResponse.key` protege a chave de criptografia do item e não remove a chave privada da passkey aninhada.

Campos de `fido2Credentials[]`: `credentialId`, `keyType`, `keyAlgorithm`, `keyCurve`, `keyValue`, `rpId`, `userHandle`, `userName`, `counter`, `rpName`, `userDisplayName`, `discoverable`, `creationDate`. `counter` e `discoverable` são **strings no formato de exportação**, apesar de contador numérico e discoverability booleana na view do cliente. Campos opcionais podem faltar. O parser não deve transformar ausência de chave em credencial utilizável.

**Confirmado:** [`createKeyView` e `getPrivateKeyFromFido2Credential`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/platform/services/fido2/fido2-authenticator.service.ts) exportam/importam `pkcs8`; criam chave ECDSA P-256, contador inicial zero. [`Fido2Utils.arrayToString`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/platform/services/fido2/fido2-utils.ts) codifica bytes em base64url **sem padding**. Assim, nesse caminho, `keyValue` é DER PKCS#8 codificado em base64url, e não PEM, JWK, COSE nem a chave pública. `userHandle` também representa bytes em base64url. Outros algoritmos/formatos não foram comprovados; devem ser rejeitados explicitamente até serem suportados.

**Confirmado:** [`parseCredentialId`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/platform/services/fido2/credential-id-utils.ts) aceita UUID convertido a bytes ou prefixo `b64.` com base64url. O identificador que o RP conhece são esses bytes; usar os caracteres UTF-8 do UUID ou gerar outro ID quebra a credencial.

**Desconhecido:** saída de uma versão publicada específica da CLI com um cofre de teste. Não se executou `bw login`, `bw list` ou `bw export`. A confirmação acima é análise estática, não demonstração de autenticação de ponta a ponta.

## Interfaces e limites

| Interface | Resultado para Linux nativo |
| --- | --- |
| Exportação JSON oficial | **Confirmado:** contém passkeys; viável como entrada manual. CSV perde material de passkey. |
| CLI Password Manager | **Confirmado:** disponível em Linux; `login`, `unlock`, `sync`, `list items`, `export` são interfaces documentadas. **Inferência:** pode servir de processo auxiliar para recuperar itens autorizados. |
| Vault Management API | **Confirmado:** interface HTTP local da CLI por `bw serve`, não serviço público remoto de OAuth do usuário. Acrescenta superfície HTTP; não é necessária para importar arquivo ou executar CLI. |
| Public API | **Confirmado:** gerencia recursos organizacionais; não fornece gerenciamento de itens individuais do cofre. |
| SDK Password Manager | Código Rust e bindings internos existem; **não é SDK público estável ou suportado**. Não é a escolha inicial para integração Python/Linux. |
| CXP/CXF | CXP é protocolo de troca; CXF é formato. Bitwarden documenta fluxo entre apps em iOS 26+ e Android 10+. Não foi localizada interface oficial de troca CXP para Linux desktop. |

Fontes oficiais: [CLI](https://bitwarden.com/help/cli/), [Password Manager APIs](https://bitwarden.com/help/bitwarden-apis/), [Public API](https://bitwarden.com/help/public-api/), [Export Vault Data](https://bitwarden.com/help/export-your-data/), [SDK API docs](https://sdk-api-docs.bitwarden.com/).

O endereço solicitado [Vault Management API](https://bitwarden.com/help/vault-management-api/) retornou nesta consulta conteúdo de navegação sem a descrição técnica. A página oficial **Password Manager APIs** e a seção `serve` da CLI confirmam a natureza local. Isso não autoriza inferir endpoints cloud ou um fluxo OAuth de terceiros.

### Exportação CLI versus interface gráfica

**Confirmado no código fixado:** [`EXPORT_FORMATS`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/tools/export-vault-core/src/services/vault-export.service.abstraction.ts) admite `csv`, `json`, `encrypted_json`, `zip`; [`ExportCommand`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/tools/export.command.ts) usa CSV por padrão. Passar `--password` junto de formato JSON seleciona exportação cifrada nesse código. Não copiar um exemplo da documentação com senha e esperar JSON em claro.

**Confirmado na documentação atual:** web, extensão e desktop oferecem JSON, CSV, JSON cifrado e ZIP; ZIP destina-se a dados individuais. Mobile tem exportação de arquivo e transferência CXP nas versões indicadas. Exportação individual exclui dados de organizações; exportação organizacional depende de função/permissões. Políticas podem impedir exportação. Não confundir disponibilidades do HEAD com versões antigas instaladas.

Exportação cifrada restrita à conta não é intercâmbio independente: depende da conta/chave original. A opção protegida por senha serve para migração entre contas Bitwarden, mas um importador externo precisaria implementar e verificar sua descriptografia. **Inferência:** para uma primeira versão, declarar somente JSON não cifrado como formato aceito evita prometer suporte inexistente; isso exige tratamento transitório e protegido do arquivo.

### Login, MFA e sessão

**Confirmado na [CLI oficial](https://bitwarden.com/help/cli/):** autenticação interativa por email/senha solicita MFA quando aplicável; os métodos listados são autenticador, email e YubiKey. Há login com chave de API pessoal e login SSO organizacional via navegador. FIDO2/Duo não têm o mesmo suporte interativo da CLI; a documentação aponta chave pessoal como alternativa. Chave de API não substitui a senha mestra para descriptografar dados. Contas que dependem exclusivamente de trusted devices podem não acessar dados pela CLI.

`bw unlock` gera a sessão usada para descriptografar o cofre. `BW_SESSION` é segredo de descriptografia local, **não token OAuth com escopos de leitura de passkeys**; `bw lock`/`logout` invalidam a sessão ativa. `bw sync` atualiza o cache; não significa sincronização automática do armazenamento de um terceiro. Não foi encontrado fluxo oficial para um aplicativo terceiro registrar client ID, pedir consentimento de passkeys e obter acesso limitado ao cofre.

Essa invalidação é a garantia operacional descrita na documentação, **não revogação criptográfica de todo segredo já copiado**. [`LockCommand`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/auth/commands/lock.command.ts) chama o serviço de bloqueio e limpa a variável do próprio processo; [`LockService`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/unlock/src/lock.service.ts) limpa chaves/cache/estado local. Um subprocesso não apaga variáveis do shell pai nem chaves/passkeys já importadas por outro programa. [`NodeEnvSecureStorageService`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/platform/services/node-env-secure-storage.service.ts) usa os bytes de `BW_SESSION` para proteger/desproteger armazenamento local. Não se comprovou replay de uma sessão anterior após bloqueio nesta fase; não prometer revogação global ou depender de apagar apenas uma variável.

**Bloqueio de requisito:** [`status`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/commands/status.command.ts) consulta o estado da CLI e pode tentar auto-unlock; isso não comprova que o desktop oficial esteja desbloqueado. O HEAD tem [`unlock` biométrico por desktop](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/key-management/commands/unlock.command.ts), mas não foi demonstrada uma assinatura pública estável de eventos de lock que revogue uma cópia externa. Exigir que a cópia Linux pare de assinar quando o desktop Bitwarden bloquear precisa de mecanismo verificável adicional; polling de `bw status` não satisfaz essa exigência por si só. Importação persistente cria uma cópia independente.

**Bloqueio de requisito: tokens em JSON.** A CLI não pode ser considerada automaticamente compatível com “nenhuma credencial de autenticação em JSON/YAML em claro”. [`CliPlatformUtilsService.supportsSecureStorage()`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/platform/services/cli-platform-utils.service.ts) retorna false; [`ServiceContainer`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/service-container/service-container.ts) fornece esse valor ao `TokenService` e usa Lowdb. [`TokenService.determineStorageLocation`, `_setAccessToken`, `setRefreshToken`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/auth/services/token.service.ts) escolhem disco quando armazenamento seguro não está disponível, exceto configuração de logout com timeout finito; no caminho de disco gravam access/refresh tokens sem cifra. [`LowdbStorageService`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/platform/services/lowdb-storage.service.ts) persiste em `data.json` com criação 0600. Permissão 0600 não é criptografia. Não se assume que timeout em memória resolva sessões entre subprocessos; seria necessário provar essa operação. Uma alternativa futura pode usar estado efêmero em memória protegida, mas não foi implementada nem validada. Importação manual evita gerenciar login/tokens Bitwarden pelo Linux-Passkey, embora o JSON exportado ainda contenha chaves privadas em claro transitoriamente.

**Inferência:** um auxiliar CLI deve ter diretório de estado próprio, sessão em memória, execução sem shell e sem registrar stdout/segredos; não deve reutilizar o estado da aplicação Bitwarden nem enviar segredo para argumentos visíveis. Não se implementou esse auxiliar nesta fase.

## BE/BS, contador e preservação de identidade

**Confirmado:** o cliente examinado gera authenticator data com BE=true e BS=true; comentário explica que suas credenciais são sincronizadas. Campos BE/BS não aparecem no objeto de exportação JSON analisado. O cliente mantém contador zero em zero e incrementa/salva no servidor quando o contador da credencial é maior que zero. Fontes: [`fido2-authenticator.service.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/platform/services/fido2/fido2-authenticator.service.ts). A [documentação de exportação](https://bitwarden.com/help/export-your-data/) alerta sobre contadores anteriores a 2024.3.1 e risco de rejeição de backups antigos.

**Inferência:** copiar chave sem preservar ID, RP ID, user handle e semântica de contador/backup é insuficiente. Não usar contador global nem transformar silenciosamente credenciais antigas de contador positivo em zero. Para credenciais modernas, preservar zero; para antigas, rejeitar inicialmente ou projetar coordenação explicitamente. Cópias com contador positivo usadas por dois autenticadores podem divergir. O BS de uma cópia externa não deve ser deduzido apenas de existir um arquivo importado: a semântica de backup e a continuidade dos flags precisam de decisão e teste com o RP. UV/UP também devem refletir verificação/presença real, não apenas os flags do Bitwarden.

**Confirmado adicional:** o [conversor CXF interno](https://github.com/bitwarden/sdk-internal/blob/839c6ca06110a7c1fde14fda086dcac096a8d675/crates/bitwarden-exporters/src/cxf/login.rs) rejeita contador positivo e exige user handle; a existência desse código não comprova transporte CXP Linux.

## SDK, linguagens e licença

O [README fixado](https://github.com/bitwarden/sdk-internal/blob/839c6ca06110a7c1fde14fda086dcac096a8d675/README.md) declara o Password Manager SDK interno, não suportado para uso público e com interface instável. O núcleo é Rust; há WASM para clientes web e UniFFI para aplicações móveis Swift/Kotlin. A documentação Rust pública não equivale a contrato de SDK externo Python; o SDK público Secrets Manager é outro produto e não oferece por isso acesso às passkeys do Password Manager.

[LICENSE do SDK](https://github.com/bitwarden/sdk-internal/blob/839c6ca06110a7c1fde14fda086dcac096a8d675/LICENSE) permite a alternativa GPLv3 para código elegível, com áreas `bitwarden_license` somente sob licença própria. A [licença SDK v2](https://github.com/bitwarden/sdk-internal/blob/839c6ca06110a7c1fde14fda086dcac096a8d675/LICENSE_SDK.txt), §§3.1–3.5, restringe usos e distribuição a terceiros, preservando os direitos das partes OSS conforme sua licença. Não presumir que todo SDK é permissivo ou redistribuível. [Clients LICENSE](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/LICENSE.txt) também distingue GPLv3 e diretório comercial. **Inferência:** preferir interface de processo da CLI ou formato de arquivo reduz acoplamento técnico; empacotamento e redistribuição ainda exigem verificar as licenças dos artefatos escolhidos.

## Bloqueios e provas restantes antes de implementar

1. Fixar versão publicada da CLI e comprovar serialização com conta e credenciais descartáveis autorizadas; não usar cofre real na investigação.
2. Verificar que o armazenamento/autenticador local preserva bytes do ID externo, chave P-256 privada, RP, user handle, contador por credencial e política BE/BS/UV; provar assinatura contra a chave pública registrada no RP.
3. Definir importação idempotente por identidade da credencial, sem substituir silenciosamente outra passkey do mesmo usuário/RP; persistência deve sobreviver a falha sem sucesso parcial.
4. Separar importação de sincronização: conflito, exclusão, múltiplas cópias e uso concorrente não têm solução pronta nos formatos examinados. Inicialmente não prometer bidirecionalidade.
5. Validar desempenho, tamanho máximo, parsing estrito, permissões e descarte de segredos; sem gerar arquivos de cofre em logs, testes ou repositório.

**Veredito:** há evidência suficiente para propor importação real por JSON/CLI em Fase 2. Integração OAuth pública limitada a passkeys, SDK público estável do Password Manager e transferência CXP Linux permanecem sem suporte confirmado; não devem aparecer como capacidades entregues.

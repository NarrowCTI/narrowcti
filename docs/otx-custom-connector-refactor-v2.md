# OTX Custom Connector - Documentacao Geral

## Objetivo

Este documento descreve a versao refatorada do conector OTX customizado do CTI
Gateway. O foco desta versao foi transformar o conector em uma base modular,
testavel e mais segura para evolucao, mantendo compatibilidade com o ambiente
Docker/OpenCTI usado no laboratorio.

## Escopo Da Versao

Esta versao cobre:

- Ingestao de pulses do OTX por queries configuraveis.
- Enriquecimento de pulses via API OTX.
- Scoring contextual antes da ingestao.
- Politica de ingestao com suporte a drop e quarantine.
- Deduplicacao persistente por pulse id.
- Exportacao para OpenCTI usando bundle STIX.
- Configuracao por variaveis de ambiente.
- Validacao automatizada por testes unitarios em Docker.

Esta versao nao implementa ainda:

- Correlacao avancada entre feeds.
- Suporte completo a multiplos conectores alem do OTX custom.
- Pipeline assincrono ou fila dedicada para ingestao.
- Interface administrativa para ajuste dinamico de policy.

## Arquitetura

O conector foi separado em modulos com responsabilidades pequenas:

```text
connectors/otx/connector.py
  Entrada do processo. Carrega settings, monta clientes e chama o runtime.

connectors/otx/runtime.py
  Loop principal do processo. Executa o processor e aguarda o intervalo
  configurado.

connectors/otx/settings.py
  Leitura e normalizacao das variaveis de ambiente.

connectors/otx/otx_client.py
  Cliente HTTP do OTX, com timeout, retries e backoff.

connectors/otx/processor.py
  Orquestracao da ingestao: queries, state, enrich, policy e exportacao.

connectors/otx/models.py
  DTOs internos do processor, como PulseCandidate e QuerySummary.

core/scoring.py
  Calculo de score e idade do pulse.

core/policy.py
  Regras de decisao de ingestao, drop e quarantine.

core/state_repository.py
  Estado persistente para evitar reprocessamento do mesmo pulse.

exporters/opencti.py
  Integracao de exportacao para OpenCTI.

exporters/stix_builder.py
  Criacao do bundle STIX, incluindo identity, report e indicators.
```

## Fluxo De Execucao

1. `connector.py` carrega as variaveis de ambiente com `load_settings()`.
2. `connector.py` cria o `OpenCTIApiClient` e o `OTXClient`.
3. `connector.py` monta o `OTXProcessor`.
4. `runtime.py` executa `processor.run_once()` dentro de loop continuo.
5. `run_once()` cria o state repository e processa cada query configurada.
6. `process_query()` busca pulses no OTX e aplica limites de revisao/ingestao.
7. `process_pulse()` valida id, verifica state, enriquece, avalia policy e ingere.
8. Apos ingestao bem-sucedida, o pulse id e marcado no state.
9. Ao fim da query, um `QuerySummary` e retornado e o resumo e registrado em log.

## Politica De Ingestao

A decisao de ingestao fica em `core/policy.py` e recebe um `PolicyConfig`.

Regras principais:

- Pulses sem data valida seguem com idade desconhecida.
- Pulses com score muito baixo podem ir para quarantine quando habilitado.
- Pulses abaixo de `MIN_SCORE_TO_INGEST` sao descartados.
- Pulses antigos precisam atingir `MIN_SCORE_FOR_OLD_PULSE`.
- `MAX_DAYS_HARD_FILTER` pode ser usado como corte absoluto de idade.

Parametros relevantes:

```text
MIN_SCORE_TO_INGEST=60
MAX_DAYS_OLD=1095
MIN_SCORE_FOR_OLD_PULSE=80
MAX_DAYS_HARD_FILTER=0
ENABLE_QUARANTINE=true
QUARANTINE_SCORE_THRESHOLD=50
```

## Estado E Deduplicacao

O state fica em arquivo JSON, por padrao:

```text
/app/state/state.json
```

No Docker Compose, esse caminho e montado a partir do workspace local:

```text
../cti-gateway/state:/app/state
```

Com isso, o conector evita reprocessar pulses ja vistos. O state so e marcado
depois que a exportacao para OpenCTI conclui com sucesso. Se a exportacao
falhar, o pulse nao e marcado e pode ser tentado novamente em uma execucao
futura.

## Variaveis De Ambiente

O exemplo versionado fica em:

```text
connectors/otx/.env.example
```

O arquivo real usado pelo container deve ficar em:

```text
connectors/otx/.env
```

O arquivo `.env` real contem segredos e nao deve ser versionado.

Variaveis obrigatorias:

```text
OPENCTI_URL
OPENCTI_TOKEN
OTX_API_KEY
OTX_QUERIES
```

Variaveis operacionais principais:

```text
CONNECTOR_NAME
CONNECTOR_RUN_INTERVAL
STATE_FILE
OTX_TIMEOUT
OTX_SEARCH_TIMEOUT
OTX_RETRIES
OTX_RETRY_BACKOFF_SECONDS
MAX_PULSES_PER_QUERY
MAX_SEARCH_RESULTS_PER_QUERY
MAX_IOCS_PER_PULSE
INGEST_PAUSE_SECONDS
```

## Docker

O Docker Compose principal fica fora deste repositorio:

```text
<lab-root>/opencti/docker-compose.yml
```

Layout esperado do ambiente local:

```text
<lab-root>/
  cti-gateway/
  opencti/
```

O servico do conector e:

```text
connector-otx-custom
```

O container criado e:

```text
otx-custom-connector
```

Comandos principais:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\opencti"
docker compose --profile otx-custom build connector-otx-custom
docker compose --profile otx-custom up -d --force-recreate connector-otx-custom
docker compose --profile otx-custom logs --tail 120 connector-otx-custom
docker compose --profile otx-custom ps connector-otx-custom
```

O aviso abaixo pode aparecer no Compose atual:

```text
the attribute `version` is obsolete
```

Esse aviso nao bloqueia a execucao. Ele indica apenas que o campo `version` do
arquivo Compose pode ser removido em uma limpeza futura.

## Desenvolvimento Desta Versao

O desenvolvimento desta versao foi feito em fatias pequenas e validadas.

Principais mudancas:

- Ajuste do build Docker para copiar `core` e `exporters` para dentro da imagem.
- Separacao de configuracao em `settings.py`.
- Extracao do cliente OTX para `otx_client.py`.
- Extracao do processor principal para `processor.py`.
- Criacao de `runtime.py` para isolar o loop continuo.
- Criacao de `models.py` para `PulseCandidate` e `QuerySummary`.
- Criacao de `PolicyConfig` em `core/policy.py`.
- Criacao de `PulseStateRepository` em `core/state_repository.py`.
- Separacao do builder STIX em `exporters/stix_builder.py`.
- Injecao de dependencias no processor:
  - exporter
  - state repository factory
  - sleeper
  - ingest pause
- Retorno de summaries estruturados por query e por execucao.
- Protecao contra pulses sem id.
- Protecao contra falha de enrich.
- Protecao para nao marcar state quando a exportacao falhar.
- Configuracao de identity STIX por `CONNECTOR_NAME`.
- Criacao de `.env.example` sem segredos.
- Separacao dos testes do processor em arquivo dedicado.

## Testes

Os testes ficam em:

```text
tests/test_core_pipeline.py
tests/test_otx_processor.py
```

O comando principal de validacao e:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\cti-gateway"
docker run --rm -v "${LAB_ROOT}\cti-gateway:/repo" -w /repo opencti-connector-otx-custom python -m unittest discover -s tests -v
```

A validacao final desta versao em 2026-05-01 passou com:

```text
Ran 16 tests
OK
```

## Validacao Final Da Imagem

Build:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\opencti"
docker compose --profile otx-custom build connector-otx-custom
```

Sintaxe Python:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\cti-gateway"
docker run --rm opencti-connector-otx-custom python -m py_compile connector.py models.py processor.py runtime.py settings.py otx_client.py core/scoring.py core/policy.py core/state_repository.py exporters/opencti.py exporters/stix_builder.py
```

Runtime:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\opencti"
docker compose --profile otx-custom up -d --force-recreate connector-otx-custom
docker compose --profile otx-custom logs --tail 120 connector-otx-custom
```

Sinais esperados nos logs:

```text
INFO:api:Health check (platform version)...
[INFO] Query: ...
[INFO] Searching OTX: ...
[INFO] Candidate: ...
[INFO] Drop: ... reason=...
[INFO] Query summary: ... reviewed=... ingested=... available=...
```

## Operacao

Para ajustar escopo de busca, edite `OTX_QUERIES` no `.env` real.

Para reduzir chamadas ao OTX:

```text
MAX_SEARCH_RESULTS_PER_QUERY
MAX_PULSES_PER_QUERY
CONNECTOR_RUN_INTERVAL
```

Para endurecer a politica contra dados antigos:

```text
MAX_DAYS_OLD
MAX_DAYS_HARD_FILTER
MIN_SCORE_FOR_OLD_PULSE
```

Para reduzir volume de indicators exportados por pulse:

```text
MAX_IOCS_PER_PULSE
```

## Cuidados

- Nao versionar `connectors/otx/.env`.
- Nao apagar `state/state.json` sem querer reprocessar pulses antigos.
- Nao executar `docker compose down -v` no ambiente OpenCTI/MISP sem backup.
- Nao executar `docker volume prune` se houver volumes persistentes importantes.
- Ao limpar disco, preferir primeiro `docker builder prune` e `docker image prune`.

## Preparacao Para PR

Antes de abrir o PR para `dev`, validar:

```powershell
$LAB_ROOT = "<path-to-lab-root>"
cd "$LAB_ROOT\cti-gateway"
git status
cd "$LAB_ROOT\opencti"
docker compose --profile otx-custom build connector-otx-custom
cd "$LAB_ROOT\cti-gateway"
docker run --rm opencti-connector-otx-custom python -m py_compile connector.py models.py processor.py runtime.py settings.py otx_client.py core/scoring.py core/policy.py core/state_repository.py exporters/opencti.py exporters/stix_builder.py
docker run --rm -v "${LAB_ROOT}\cti-gateway:/repo" -w /repo opencti-connector-otx-custom python -m unittest discover -s tests -v
```

Sugestao de titulo:

```text
refactor: modularize OTX connector pipeline foundation
```

Resumo sugerido:

```text
This PR modularizes the custom OTX connector foundation, separating settings,
OTX client access, processing flow, policy, state repository and STIX export.
It also adds focused unit coverage, Docker validation, runtime documentation
and a safe env example for local deployment.
```

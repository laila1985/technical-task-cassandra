# PCAP Processor

A standalone Java application for processing PCAP network-capture files and
storing the parsed data in a Cassandra database.

## Requirements

- **CentOS 7** (or any Linux; also runs on Windows for development)
- **Java 8** (JDK)
- **Cassandra 3** (for the `cassandra` storage mode)

## Design constraints met

- **No Spring** — plain JDK only.
- **No Hibernate** — a hand-written Cassandra CQL native protocol (v4) client
  is used (no DataStax driver).
- **No Maven / Gradle** — plain `javac` + `jar` build scripts.

## Build & run

### With Docker (recommended — Cassandra + JDK 8 as images)

No local JDK or Cassandra needed; both run as containers.

```bash
docker compose up -d --build
```

This starts:

- **`cassandra:3.11`** — a real Cassandra 3 node (port `9042`, persistent
  volume `cassandra_data`).
- **`app`** — the PCAP processor built in a multi-stage
  `eclipse-temurin:8-jdk` → `eclipse-temurin:8-jre` image (plain `javac`, no
  Maven/Gradle).

Drop PCAP files into the host `./input` folder; the watcher picks them up and
stores parsed data in Cassandra. Extracted images appear in `./output/images`.

```bash
docker compose logs -f app                 # follow processing logs
docker exec pcap-cassandra cqlsh -e "SELECT * FROM pcap_analysis.captures;"
docker compose down                        # stop (keeps data in the volume)
docker compose down -v                     # stop and wipe Cassandra data
```

Configuration is passed via environment variables in `docker-compose.yml`
(each `application.properties` key is overridable with its dotted name
uppercased and dots replaced by underscores, e.g.
`CASSANDRA_CONTACT_POINTS=cassandra`).

### Native build (CentOS 7 / JDK 8)

```bash
./build.sh
./bin/run.sh --config conf/application.properties
```


## Configuration

See `conf/application.properties`. Key settings:

| Key | Meaning |
|-----|---------|
| `input.folder` | folder scanned for new PCAP files |
| `storage.mode` | `cassandra`, `file`, or `none` |
| `threads.count` | max concurrent files (Level 2) |
| `db.batch.size` | packets buffered per Cassandra batch |
| `cassandra.contact.points` / `.port` / `.keyspace` | DB connection |
| `image.content.types` | content types to extract (Level 5) |

Use `storage.mode=file` to validate the pipeline without a Cassandra node;
it writes JSON/CSV to `output/data`.

## Command line

```
java com.pcap.Application [--config path] [--ui] [--once file.pcap]
```

- No args: watches the input folder continuously.
- `--ui`: also opens the Swing search window (Level 4).
- `--once file.pcap`: process a single file and exit (handy for testing).

## Feature map

- **Level 1** — input-folder polling (`FolderWatcher`), PCAP parsing
  (`PcapParser` + `PcapDecoder`), file statistics and records/sec metrics
  (`Statistics`).
- **Level 2** — bounded thread pool for concurrent files; configuration file
  with DB parameters and thread limits.
- **Level 3** — stores packets (protocols, MAC/IP, ports, timestamps) and
  aggregations (duration, packet/byte counts) to Cassandra.
- **Level 4** — keyspace schema (`schema/schema.cql`, also auto-created at
  startup) and a Swing UI to search by protocol and IP.
- **Level 5** — extracts images from HTTP responses/requests and writes them
  to `output/images/<fileId>/` with DB mapping (`images` table).

## Cassandra schema

Defined in `schema/schema.cql` and bootstrapped automatically by the app:

- `captures` — one row per file (aggregation).
- `packets` — detailed packet records (partition by `file_id`, cluster by
  `packet_index`).
- `protocols`, `ip_pairs`, `endpoints` — aggregations.
- `images` — extracted images mapped to files.

Secondary indexes on `packets(protocol|src_ip|dst_ip)` support the search UI.

## Testing

A synthetic PCAP generator is included:

```bash
javac -d build/test test/PcapGen.java
java -cp build/test PcapGen input/test.pcap
java -cp build/classes com.pcap.Application --config conf/test.properties --once input/test.pcap
```

It produces Ethernet/IPv4/TCP/HTTP and UDP packets and verifies parsing,
aggregation, and image extraction end-to-end (using `storage.mode=file`).

To validate against the real Cassandra running in Docker, just drop the
generated file into `./input` while the stack is up:
`docker exec pcap-cassandra cqlsh -e "SELECT count(*) FROM pcap_analysis.packets;"`

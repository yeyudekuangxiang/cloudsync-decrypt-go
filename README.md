# cloudsync-decrypt

Go 语言实现的 Synology Cloud Sync 加密文件（`__CLOUDSYNC_ENC__`）**加解密**工具，
既是 **可 `import` 的库**，也是 **一条命令行**。

主要面向以下场景：

- 用户手上有一批 Synology NAS 生成的 `.enc` 文件，想在没有原厂 GUI 工具的
  情况下（尤其是 macOS、Windows Server、Linux 无桌面环境）恢复出明文。
- 想把解密嵌入到自己的 Go 服务里，直接把加密流接到图片解码器 / 视频播放器 /
  HTTP 上传器，不落盘。
- 想批量、并发地把整个目录树解出来，还保留原目录结构与 mtime。
- 想在自己的服务里**生成**兼容格式的加密文件（比如做数据迁移、异地备份或
  roundtrip 校验），用密码或公钥任一或同时作为恢复凭证。

## 特性

- **纯 Go 实现**，不依赖 CGO，不需要 OpenSSL 环境。跨平台（macOS / Linux /
  Windows）单二进制发布。
- **兼容 v1、v3.0、v3.1** 三个版本的 csenc 流（读+写）。
- **加密与解密双向**：加密时可写 `enc_key1`（密码路径）和/或 `enc_key2`（RSA
  公钥路径），生成的文件用密码或对应私钥都能解开。
- **两条恢复路径**：用户密码（`enc_key1`）或 RSA 私钥（`enc_key2`）。
- **流式接口**：`io.Reader` → `io.Reader`（解密方向），`io.Writer` 包装
  （加密方向），可直接接下游消费者。
- **批量库函数**：递归目录、并发处理、skip-existing 幂等、保留 mtime、失败
  不中断，通过回调驱动进度。
- **只依赖一个第三方包**：`github.com/pierrec/lz4/v4`。其余全部走 Go 标准库
  （`crypto/aes`、`crypto/rsa`、`crypto/md5`、`crypto/sha1`、`encoding/base64`
   ……）。

## 安装

作为库：

```bash
go get github.com/yeyu/cloudsync-decrypt/csenc
```

作为命令行工具：

```bash
go install github.com/yeyu/cloudsync-decrypt/cmd/cloudsync-decrypt@latest
```

或从源码构建：

```bash
git clone <this-repo>
cd cloudsync-decrypt
go build -o cloudsync-decrypt ./cmd/cloudsync-decrypt
```

> **模块路径**：仓库里默认的 `module` 是 `github.com/yeyu/cloudsync-decrypt`，
> 如果你把项目推到别的位置，请 `go mod edit -module <your-path>` 并把 `cmd/`
> 与测试文件里的 `import` 一起改掉。

## 快速开始

### 库 —— 流式解密（推荐）

```go
package main

import (
    "io"
    "os"

    "github.com/yeyu/cloudsync-decrypt/csenc"
)

func main() {
    r, err := csenc.OpenFile("photo.enc", csenc.Options{
        Password: []byte("your-password"),
    })
    if err != nil {
        panic(err)
    }
    defer r.Close()

    // 直接把明文接到任意下游消费者：解码器、hash、http body...
    _, _ = io.Copy(os.Stdout, r)
}
```

从 `io.Reader` 到 `io.Reader`（用于 HTTP 响应体、`bytes.Buffer` 等场景）：

```go
r := csenc.NewReader(source, csenc.Options{Password: pw})
defer r.Close()

img, _ := jpeg.Decode(r)            // 流入图片解码器
h := sha256.New(); io.Copy(h, r)    // 或流入哈希
```

只想拿元数据、不需要密码：

```go
meta, err := csenc.InspectFile("photo.enc")
fmt.Println(meta.Filename, meta.Compress, meta.Encrypt) // 原文件名 / 是否压缩 / 是否加密
```

批量目录（递归 + 并发 + 幂等）：

```go
report := csenc.Batch(csenc.BatchConfig{
    Inputs:       []string{"/nas/photos", "/nas/videos"},
    OutputDir:    "/recovered",
    Password:     pw,
    Recursive:    true,
    Concurrency:  8,
    SkipExisting: true,
    PreserveTime: true,
    OnEvent: func(e csenc.BatchEvent) {
        // 并发安全；驱动进度条 / 结构化日志都可以
    },
})
fmt.Println(report.Format())
for _, e := range report.Errors { /* 单个失败不会打断整批 */ }
```

### 库 —— 加密

生成一份 csenc 文件（同时支持密码与公钥两条恢复路径）：

```go
pub, _ := csenc.LoadRSAPublicKey("public.pem")

err := csenc.EncryptFile("photo.jpg", "photo.jpg.enc", csenc.EncryptOptions{
    Password:  []byte("recovery-password"),
    PublicKey: pub,       // 可选；提供后接收方也能用对应私钥打开
    // Major/Minor 默认 3.1；Compress 默认 true
    Filename:  "photo.jpg", // 元数据里的原始文件名
})
```

流式加密（`io.Reader` 明文 → `io.Writer` 密文），用于把加密链接到网络上传等
场景，不落盘：

```go
w, _ := csenc.NewWriter(dst, csenc.EncryptOptions{Password: pw})
_, _ = io.Copy(w, src)  // src 是任何 io.Reader
w.Close()               // 必须 Close，写尾部 file_md5
```

或者一次性 `Encrypt(r io.Reader, w io.Writer, opts)`：

```go
_ = csenc.Encrypt(bytes.NewReader(plaintext), out, csenc.EncryptOptions{
    Password: pw,
    Major:    1, Minor: 0,  // 生成 v1 兼容格式
})
```

### CLI

#### 解密（默认模式）

密码文件（推荐，避免 shell history 泄露）：

```bash
echo -n 'your-password' > pw.txt

# 单个文件
cloudsync-decrypt -password-file pw.txt -o decrypted.docx encrypted.docx

# 目录递归 + 8 并发 + 保留 mtime
cloudsync-decrypt -r -j 8 -password-file pw.txt -outdir /recovered /nas/photos

# 幂等重跑（已解密过的自动跳过）
cloudsync-decrypt -r -skip-existing -password-file pw.txt -outdir /recovered /nas

# 只看元数据，不解密（不需要密码）
cloudsync-decrypt -inspect -r /nas
```

用 RSA 私钥而非密码：

```bash
cloudsync-decrypt -private-key private.pem -outdir /recovered /nas/photos
# 私钥自身有口令时
cloudsync-decrypt -private-key private.pem -private-key-password 'pkpw' ...
```

#### 加密

通过 `-encrypt` 切到加密方向，其余 flag 语义一致：

```bash
# 单文件，用密码加密
cloudsync-decrypt -encrypt -password-file pw.txt -o photo.jpg.enc photo.jpg

# 同时写入密码路径 + 公钥路径（接收方任一条都能解）
cloudsync-decrypt -encrypt -password-file pw.txt -public-key public.pem \
    -o photo.jpg.enc photo.jpg

# 目录递归 + 并发批量加密
cloudsync-decrypt -encrypt -r -j 8 -password-file pw.txt \
    -outdir /encrypted /source/photos

# 指定生成 v1 格式（默认 3.1；也支持 3.0）
cloudsync-decrypt -encrypt -version 1.0 -password-file pw.txt -o x.enc x.txt

# 关掉 LZ4 压缩（对已压缩内容如 mp4/jpg 加密稍微省点 CPU）
cloudsync-decrypt -encrypt -compress=false -password-file pw.txt -o x.enc x.mp4
```

## 库 API

### 核心类型

```go
type Options struct {
    Password   []byte              // 走 enc_key1 路径
    PrivateKey *rsa.PrivateKey     // 走 enc_key2 路径（RSA-OAEP + SHA-1）
    OnMetadata func(*Metadata)     // 头部解析完毕、正式解密开始前触发一次
    Logger     func(string, ...any)
}

type Metadata struct {
    Major, Minor   int64
    Salt           []byte
    Digest         string   // 目前仅见 "md5"
    EncKey1        []byte
    EncKey2        []byte
    Key1Hash       string
    SessionKeyHash string
    PlaintextMD5   string   // 尾部字段；Inspect 阶段可能还是空
    Filename       string   // 原始文件名
    Compress       int64    // 1 = LZ4, 0 = 无压缩
    Encrypt        int64    // 1 = AES-256-CBC, 0 = 未加密
}
```

### 入口函数

解密方向：

| 函数 | 用途 |
|---|---|
| `csenc.NewReader(r io.Reader, opts) *Reader` | Reader ↔ Reader 流式接口 |
| `csenc.OpenFile(path, opts) (*Reader, error)` | 文件路径直接开 Reader，Close 一并关文件 |
| `csenc.DecryptFile(inPath, outPath string, opts) error` | 单文件落盘，走临时文件 + 原子 rename |
| `csenc.Decrypt(r io.Reader, w io.Writer, opts) error` | 底层 writer 语义 |
| `csenc.Inspect(r io.Reader) (*Metadata, error)` | 只读元数据 |
| `csenc.InspectFile(path) (*Metadata, error)` | 只读元数据（文件版） |
| `csenc.IsCsencFile(path) (bool, error)` | 仅看 magic |
| `csenc.LoadRSAPrivateKey(path, passphrase) (*rsa.PrivateKey, error)` | PEM → 私钥 |
| `csenc.Batch(cfg BatchConfig) *BatchReport` | 递归 + 并发批量 |

加密方向：

| 函数 | 用途 |
|---|---|
| `csenc.NewWriter(w io.Writer, opts EncryptOptions) (*Writer, error)` | 流式加密，Write 明文，Close 收尾 |
| `csenc.Encrypt(r io.Reader, w io.Writer, opts EncryptOptions) error` | 一次性 Reader→Writer 加密 |
| `csenc.EncryptFile(inPath, outPath string, opts EncryptOptions) error` | 单文件加密，原子 rename |
| `csenc.LoadRSAPublicKey(path) (*rsa.PublicKey, error)` | PEM → 公钥（支持 PKIX 与 PKCS#1） |

`EncryptOptions`：

```go
type EncryptOptions struct {
    Password   []byte           // 生成 enc_key1，接收方能用密码解
    PublicKey  *rsa.PublicKey   // 生成 enc_key2，接收方能用对应私钥解
    Major, Minor int64          // 默认 3.1；也可写 3.0 / 1.0
    Filename   string           // 存入 metadata.file_name
    Compress   *bool            // nil = true；显式 false 关掉 LZ4
    Rand       io.Reader        // 默认 crypto/rand.Reader
    Logger     func(string, ...any)
}
```

Password 与 PublicKey **至少要给一个**，两个都给时两条恢复路径同时可用。

### `*Reader` 使用要点

- 实现 `io.ReadCloser`。**必须调用 `Close()`**，否则后台 goroutine 会泄漏。
- `Close()` 是幂等的；提前 Close（没读完就走了）不会误报 `pipe closed`。
- 尾部完整性错误（`file_md5` 校验失败等）会从 `Close()` 返回，别忽略。
- `r.Metadata()` 在 `OnMetadata` 触发后可用；返回的是快照拷贝，可以随意存。

### 批量事件

```go
type BatchEventKind int
const (
    EventDiscovered BatchEventKind = iota // 枚举阶段
    EventSucceeded
    EventSkipped
    EventFailed
)
```

`OnEvent` 会在 worker goroutine 里回调，请自己加锁。

## CLI 参考

```
usage: cloudsync-decrypt [flags] input [input ...]
       cloudsync-decrypt -encrypt [flags] input [input ...]
       cloudsync-decrypt -inspect [flags] input [input ...]

模式开关：
  -encrypt                       加密而不是解密
  -inspect                       只打印每个输入的 metadata（JSON），不做加/解密

密钥材料：
  -password-file string          存密码的文件（推荐；尾部换行会被剥掉）
  -password string               命令行明文密码（会通过 /proc 暴露；仅 debug 用）
  -private-key string            PEM 私钥文件（解密时用）
  -private-key-password string   私钥本身的口令
  -public-key string             PEM 公钥文件（加密时用）

输入 / 输出：
  -o string                      单文件输出路径（不能与 -r 一起用）
  -outdir string                 批量输出根目录；目录输入的相对结构会被镜像
  -r                             递归目录
  -j int                         并发 worker 数（默认 GOMAXPROCS）
  -skip-existing                 目标文件已存在则跳过
  -preserve-time                 保留源文件 mtime（默认 true）
  -v                             打印非致命告警

加密专用：
  -version string                写出的 csenc 版本，"3.1"（默认）/ "3.0" / "1.0"
  -compress                      LZ4 压缩明文再加密（默认 true）
```

批量运行输出示例：

```
[decrypt 1/5] OK  /nas/photos/01.jpg (2.1MB -> 2.1MB, 42ms)
[decrypt 2/5] OK  /nas/photos/02.jpg (1.7MB -> 1.7MB, 39ms)
...
==========================================
discovered=5 succeeded=5 skipped=0 failed=0 bytes_in=9.4MB bytes_out=9.4MB elapsed=210ms
```

## 协议概览

不打算在 README 里贴完整的字节级说明，简要提示：

- 文件头：`__CLOUDSYNC_ENC__`（17 字节） + `hex(md5(magic))`（32 字节）
- 之后是变长的 **PObject 对象流**，1 字节 type prefix：`0x40` end / `0x42`
  dict / `0x11` bytes（`u16be` 长度） / `0x10` string / `0x01` int
- 每个 dict 有 `type = "metadata"` 或 `type = "data"`
- 密钥派生：**OpenSSL `EVP_BytesToKey` (MD5)**，有 salt 时 1000 轮，无 salt 1 轮
- 数据加密：**AES-256-CBC + PKCS7**，可选 **LZ4 Frame** 压缩
- 密码路径：`EVP_BytesToKey(password, salt) → AES-CBC 解 enc_key1`
- 私钥路径：`RSA / PKCS#1 OAEP with SHA-1 → 解 enc_key2`
- v3+ 的 session key 是 ASCII hex，取出后要 `hex.DecodeString` 再作为下一层
  KDF 的输入

完整协议还原过程可参见 [marnix/synology-decrypt](https://github.com/marnix/synology-decrypt)
的 `syndecrypt/core.py`（GPL-3.0），本项目仅参考其中的协议事实，未搬运源码。

## 测试

```bash
go test ./csenc/...
```

大部分测试用例是拿真实向量比对 bit-for-bit 一致。测试向量默认从
`/tmp/synology-decrypt/tests/` 读，可以先把参考实现的仓库 clone 到那里：

```bash
git clone https://github.com/marnix/synology-decrypt /tmp/synology-decrypt
```

如果目录不存在，相关用例会自动 `Skip` 而不是失败——包本身仍然能 `go test`
干净通过。

覆盖场景：

- 底层 `Decrypt`：5 密码路径 + 5 私钥路径 + 1 错密码用例
- `Reader` API：流式读、元数据回调、早关抑制、`OpenFile` 关联关闭、下游
  chained consumer
- 元数据：`IsCsencFile`、`InspectFile`
- `Batch`：递归目录镜像、`SkipExisting` 幂等、缺失输入不中断
- 加密 roundtrip：v1 / v3.0 / v3.1 三个版本 × 密码路径 × 私钥路径；空文件、
  纯二进制大数据、关闭压缩、拒绝无密钥、`EncryptFile` 与 `DecryptFile` 端到端

## 项目结构

```
cloudsync-decrypt-go/
├── go.mod
├── csenc/
│   ├── csenc.go       # magic 常量 + 包 doc
│   ├── wire.go        # PObject wire codec
│   ├── kdf.go          # OpenSSL EVP_BytesToKey
│   ├── hash.go         # salted md5 envelope
│   ├── decrypt.go      # Metadata / Inspect / Decrypt / 解密流水线
│   ├── reader.go       # NewReader + *Reader + OnMetadata 桥
│   ├── encrypt.go      # EncryptOptions / Writer / Encrypt / EncryptFile / wire encoder
│   ├── file.go         # OpenFile / DecryptFile / InspectFile / IsCsencFile / LoadRSAPrivateKey / LoadRSAPublicKey
│   ├── batch.go        # BatchConfig / Batch / BatchEvent / BatchReport
│   ├── decrypt_test.go
│   ├── encrypt_test.go
│   ├── reader_test.go
│   └── batch_test.go
└── cmd/cloudsync-decrypt/
    └── main.go         # 薄壳 CLI，实际逻辑全部委托 csenc
```

## 已知限制 / 路线图

- **只支持 `encrypt=1, compress in {0,1}`**。`encrypt=0` 目前会明确报错，
  真实文件里也没见过这个组合。
- **`key2_hash` 未校验**。这个字段的确切原像在公开规范里没定义，官方工具
  本身也把它当作信息性字段。不影响解密正确性。
- **符号链接** 在 `filepath.WalkDir` 下走默认行为（不追随），必要时可通过
  `BatchConfig.Filter` 自行处理。
- **性能**：真实文件里 `compress=1` 是常态，即便对 H.264 视频、JPEG 图片
  这类高熵内容也一样，因此 AES → LZ4 阶段无法跳过。批量视频吞吐进一步优化
  的方向是把 LZ4 阶段从跨 goroutine `io.Pipe` 换成同 goroutine 里 `bufio` +
  `lz4frame.Decoder` 直调。

package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"io"

	"github.com/zeebo/blake3" // Изменённый импорт
)

type version_metadata struct {
	majorVer  uint16
	minorVer  uint16
	publicKey ed25519.PublicKey
	priority  uint8
}

const (
	ProtocolVersionMajor uint16 = 0
	ProtocolVersionMinor uint16 = 6
)

const (
	metaVersionMajor uint16 = iota
	metaVersionMinor
	metaPublicKey
	metaPriority
)

type handshakeError string

func (e handshakeError) Error() string { return string(e) }

const (
	ErrHandshakeInvalidPreamble   = handshakeError("invalid handshake, remote side is not Ruvchain")
	ErrHandshakeInvalidLength     = handshakeError("invalid handshake length, possible version mismatch")
	ErrHandshakeInvalidPassword   = handshakeError("invalid password supplied, check your config")
	ErrHandshakeHashFailure       = handshakeError("invalid hash length")
	ErrHandshakeIncorrectPassword = handshakeError("password does not match remote side")
)

func version_getBaseMetadata() version_metadata {
	return version_metadata{
		majorVer: ProtocolVersionMajor,
		minorVer: ProtocolVersionMinor,
	}
}

func (m *version_metadata) encode(privateKey ed25519.PrivateKey, password []byte) ([]byte, error) {
	bs := make([]byte, 0, 64)
	bs = append(bs, 'm', 'e', 't', 'a')
	bs = append(bs, 0, 0) // Placeholder for length

	// Добавляем поля метаданных
	bs = binary.BigEndian.AppendUint16(bs, metaVersionMajor)
	bs = binary.BigEndian.AppendUint16(bs, 2)
	bs = binary.BigEndian.AppendUint16(bs, m.majorVer)

	bs = binary.BigEndian.AppendUint16(bs, metaVersionMinor)
	bs = binary.BigEndian.AppendUint16(bs, 2)
	bs = binary.BigEndian.AppendUint16(bs, m.minorVer)

	bs = binary.BigEndian.AppendUint16(bs, metaPublicKey)
	bs = binary.BigEndian.AppendUint16(bs, ed25519.PublicKeySize)
	bs = append(bs, m.publicKey[:]...)

	bs = binary.BigEndian.AppendUint16(bs, metaPriority)
	bs = binary.BigEndian.AppendUint16(bs, 1)
	bs = append(bs, m.priority)

	// Генерация ключа из пароля с помощью BLAKE3
	keyHasher := blake3.New()
	if _, err := keyHasher.Write(password); err != nil {
		return nil, err
	}
	key := keyHasher.Sum(nil)[:32] // Усекаем до 32 байт

	// Создаём keyed hasher с полученным ключом
	hasher := blake3.NewKeyed(key)
	if _, err := hasher.Write(m.publicKey); err != nil {
		return nil, err
	}

	// Получаем хеш фиксированного размера 64 байта
	hash := make([]byte, 64)
	if _, err := hasher.Digest().Read(hash); err != nil {
		return nil, err
	}

	// Добавляем подпись
	bs = append(bs, ed25519.Sign(privateKey, hash)...)

	// Обновляем длину сообщения
	binary.BigEndian.PutUint16(bs[4:6], uint16(len(bs)-6)
	return bs, nil
}

func (m *version_metadata) decode(r io.Reader, password []byte) error {
	bh := [6]byte{}
	if _, err := io.ReadFull(r, bh[:]); err != nil {
		return err
	}

	// Проверка преамбулы
	if !bytes.Equal(bh[:4], []byte{'m', 'e', 't', 'a'}) {
		return ErrHandshakeInvalidPreamble
	}

	// Чтение основной части сообщения
	hl := binary.BigEndian.Uint16(bh[4:6])
	if hl < ed25519.SignatureSize {
		return ErrHandshakeInvalidLength
	}

	bs := make([]byte, hl)
	if _, err := io.ReadFull(r, bs); err != nil {
		return err
	}

	// Отделяем подпись от данных
	sig := bs[len(bs)-ed25519.SignatureSize:]
	bs = bs[:len(bs)-ed25519.SignatureSize]

	// Парсим поля метаданных
	for len(bs) >= 4 {
		op := binary.BigEndian.Uint16(bs[:2])
		oplen := binary.BigEndian.Uint16(bs[2:4])
		bs = bs[4:]

		if len(bs) < int(oplen) {
			break
		}

		switch op {
		case metaVersionMajor:
			m.majorVer = binary.BigEndian.Uint16(bs[:2])
		case metaVersionMinor:
			m.minorVer = binary.BigEndian.Uint16(bs[:2])
		case metaPublicKey:
			m.publicKey = make([]byte, ed25519.PublicKeySize)
			copy(m.publicKey, bs[:ed25519.PublicKeySize])
		case metaPriority:
			m.priority = bs[0]
		}

		bs = bs[oplen:]
	}

	// Верификация с использованием BLAKE3
	keyHasher := blake3.New()
	if _, err := keyHasher.Write(password); err != nil {
		return ErrHandshakeInvalidPassword
	}
	key := keyHasher.Sum(nil)[:32]

	hasher := blake3.NewKeyed(key)
	if _, err := hasher.Write(m.publicKey); err != nil {
		return ErrHandshakeHashFailure
	}

	hash := make([]byte, 64)
	if _, err := hasher.Digest().Read(hash); err != nil {
		return ErrHandshakeHashFailure
	}

	if !ed25519.Verify(m.publicKey, hash, sig) {
		return ErrHandshakeIncorrectPassword
	}

	return nil
}

func (m *version_metadata) check() bool {
	if m.majorVer != ProtocolVersionMajor {
		return false
	}
	if m.minorVer != ProtocolVersionMinor {
		return false
	}
	if len(m.publicKey) != ed25519.PublicKeySize {
		return false
	}
	return true
}

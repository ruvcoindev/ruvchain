// core_test.go
package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gologme/log"
	"github.com/ruvcoindev/ruvchain/src/config"
	"github.com/stretchr/testify/require"
)

// TestMain устанавливает общие настройки для всех тестов
func TestMain(m *testing.M) {
	log.DisableLogging()
	os.Exit(m.Run())
}

// TestCoreStructure проверяет базовую структуру ядра
func TestCoreStructure(t *testing.T) {
	cfg := config.GenerateConfig()
	require.NoError(t, cfg.GenerateSelfSignedCertificate(), "Генерация сертификата")

	logger := log.New(os.Stderr, "TEST: ", 0)
	
	t.Run("Создание нового экземпляра", func(t *testing.T) {
		instance, err := New(cfg, logger)
		require.NoError(t, err, "Создание ядра")
		require.NotNil(t, instance, "Экземпляр не должен быть nil")
		instance.Stop()
	})

	t.Run("Дублированное создание", func(t *testing.T) {
		instance, _ := New(cfg, logger)
		defer instance.Stop()
		
		_, err := New(cfg, logger)
		require.Error(t, err, "Ожидалась ошибка при дублировании")
	})
}

// TestNetworkOperations проверяет сетевые операции
func TestNetworkOperations(t *testing.T) {
	cfgA := config.GenerateConfig()
	cfgB := config.GenerateConfig()
	require.NoError(t, cfgA.GenerateSelfSignedCertificate())
	require.NoError(t, cfgB.GenerateSelfSignedCertificate())

	logger := log.New(os.Stderr, "NETWORK: ", 0)

	nodeA, err := New(cfgA, logger)
	require.NoError(t, err)
	defer nodeA.Stop()

	nodeB, err := New(cfgB, logger)
	require.NoError(t, err)
	defer nodeB.Stop()

	t.Run("Установка соединения", func(t *testing.T) {
		listener, err := nodeA.Listen("tcp://127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()

		peerURL := "tcp://" + listener.Addr().String()
		require.NoError(t, nodeB.Connect(peerURL))

		require.Eventually(t, func() bool {
			return len(nodeA.Peers()) > 0 && len(nodeB.Peers()) > 0
		}, 5*time.Second, 100*time.Millisecond, "Нет подключенных пиров")
	})

	t.Run("Передача данных", func(t *testing.T) {
		testPayload := []byte("test payload")
		done := make(chan struct{})

		go func() {
			buf := make([]byte, 1024)
			n, _, err := nodeA.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, testPayload, buf[:n])
			close(done)
		}()

		_, err := nodeB.WriteTo(testPayload, nodeA.LocalAddr())
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Таймаут передачи данных")
		}
	})
}

// TestSecurityFeatures проверяет функции безопасности
func TestSecurityFeatures(t *testing.T) {
	cfg := config.GenerateConfig()
	require.NoError(t, cfg.GenerateSelfSignedCertificate())

	logger := log.New(os.Stderr, "SECURITY: ", 0)
	
	t.Run("Проверка пароля", func(t *testing.T) {
		cfg.Core.Password = "securepassword123"
		node, err := New(cfg, logger)
		require.NoError(t, err)
		defer node.Stop()

		require.True(t, node.checkPasswordAuth("securepassword123"), "Валидный пароль")
		require.False(t, node.checkPasswordAuth("wrongpassword"), "Невалидный пароль")
	})

	t.Run("Проверка подписи", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		data := []byte("important data")
		signature := ed25519.Sign(privateKey, data)

		require.True(t, ed25519.Verify(publicKey, data, signature), "Верификация подписи")
	})
}

// TestConfigurationHandling проверяет обработку конфигурации
func TestConfigurationHandling(t *testing.T) {
	t.Run("Генерация ключей", func(t *testing.T) {
		cfg := config.GenerateConfig()
		require.NoError(t, cfg.GenerateSelfSignedCertificate())
		
		require.NotEmpty(t, cfg.Core.PrivateKey, "Приватный ключ")
		require.NotEmpty(t, cfg.Core.PublicKey, "Публичный ключ")
	})

	t.Run("Сериализация конфига", func(t *testing.T) {
		cfg := config.GenerateConfig()
		cfg.Core.Password = "testpassword"
		
		buf, err := cfg.ToBytes()
		require.NoError(t, err)
		require.NotEmpty(t, buf, "Сериализованные данные")
		
		newCfg, err := config.FromBytes(buf)
		require.NoError(t, err)
		require.Equal(t, cfg.Core.Password, newCfg.Core.Password, "Пароль должен совпадать")
	})
}

// BenchmarkNetworkPerformance тестирует производительность сети
func BenchmarkNetworkPerformance(b *testing.B) {
	cfgA := config.GenerateConfig()
	cfgB := config.GenerateConfig()
	cfgA.GenerateSelfSignedCertificate()
	cfgB.GenerateSelfSignedCertificate()

	logger := log.New(os.Stderr, "BENCH: ", 0)
	
	nodeA, _ := New(cfgA, logger)
	defer nodeA.Stop()
	
	nodeB, _ := New(cfgB, logger)
	defer nodeB.Stop()

	listener, _ := nodeA.Listen("tcp://127.0.0.1:0")
	defer listener.Close()
	
	nodeB.Connect("tcp://" + listener.Addr().String())

	payload := bytes.Repeat([]byte{0x01}, 1500)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nodeB.WriteTo(payload, nodeA.LocalAddr())
		}
	})
}

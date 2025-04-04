package core

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"testing"
)

func TestVersionPasswordAuth(t *testing.T) {
	// Определяем вспомогательную функцию для нормализации паролей
	normalizePassword := func(pwd []byte) []byte {
		if pwd == nil {
			return []byte{}
		}
		return pwd
	}

	tests := []struct {
		password1 []byte
		password2 []byte
		allowed   bool
	}{
		{nil, nil, true},                      // Оба пароля не заданы
		{nil, []byte{}, true},                 // Нулевой и пустой пароль
		{[]byte{}, []byte(""), true},          // Оба пустых пароля
		{nil, []byte("foo"), false},           // Пароль только у второй ноды
		{[]byte("foo"), []byte{}, false},      // Пароль только у первой ноды
		{[]byte("foo"), []byte("foo"), true},  // Одинаковые пароли
		{[]byte("foo"), []byte("bar"), false}, // Разные пароли
	}

	for _, tt := range tests {
		// Генерация ключей для тестовой ноды
		pk, sk, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Ошибка генерации ключей: %v", err)
		}

		// Кодирование метаданных с нормализацией пароля
		metadata := &version_metadata{publicKey: pk}
		encoded, err := metadata.encode(sk, normalizePassword(tt.password1))
		if err != nil {
			t.Fatalf("Ошибка кодирования: %v", err)
		}

		// Декодирование с проверкой пароля
		var decoded version_metadata
		err = decoded.decode(bytes.NewReader(encoded), normalizePassword(tt.password2))
		
		// Проверка соответствия ожидаемого результата
		if (err == nil) != tt.allowed {
			t.Errorf("Тест %v -> %v: ожидалось %v, получено %v (ошибка: %v)",
				tt.password1, tt.password2, tt.allowed, err == nil, err)
		}
	}
}

func TestVersionRoundtrip(t *testing.T) {
	passwords := [][]byte{
		nil, 
		[]byte(""), 
		[]byte("secret_password"),
	}

	testCases := []*version_metadata{
		{majorVer: 1, minorVer: 0},
		{majorVer: 2, minorVer: 4, priority: 1},
		{majorVer: 3, minorVer: 1, priority: 5},
	}

	for _, pwd := range passwords {
		for _, tc := range testCases {
			// Генерация ключей
			pk, sk, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatalf("Ошибка генерации ключей: %v", err)
			}
			tc.publicKey = pk

			// Нормализация пароля
			normalizedPwd := pwd
			if normalizedPwd == nil {
				normalizedPwd = []byte{}
			}

			// Кодирование и декодирование
			encoded, err := tc.encode(sk, normalizedPwd)
			if err != nil {
				t.Fatalf("Ошибка кодирования: %v", err)
			}

			var decoded version_metadata
			if err := decoded.decode(bytes.NewReader(encoded), normalizedPwd); err != nil {
				t.Fatalf("Ошибка декодирования: %v", err)
			}

			// Проверка целостности данных
			if !reflect.DeepEqual(tc, &decoded) {
				t.Fatalf("Данные не совпадают:\nОжидалось: %+v\nПолучено: %+v", tc, decoded)
			}
		}
	}
}

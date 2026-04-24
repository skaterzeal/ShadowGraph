# Özet

<!-- Bu PR ne değiştiriyor? 1–3 cümle yeterli. -->

## Değişikliğin türü

- [ ] Bug fix
- [ ] Yeni özellik
- [ ] Refactor / kod iyileştirmesi
- [ ] Test / CI
- [ ] Doküman

## İlgili Issue

<!-- Fixes #123 formatında yaz, PR merge edilince otomatik kapansın. -->

## Test planı

<!-- Nasıl test ettin? Komutlar, test ağı, beklenen çıktı. -->

- [ ] `go vet ./...` temiz
- [ ] `go test ./...` yeşil
- [ ] Manuel doğrulama yapıldı:
  - [ ] `shadowgraph scan -t 127.0.0.1`
  - [ ] `shadowgraph ui`
  - [ ] `shadowgraph analyze`

## Breaking change var mı?

- [ ] Hayır
- [ ] Evet — aşağıda anlat

## Kontrol listesi

- [ ] Kod `go fmt` ile formatlandı.
- [ ] Yeni bir dışa açık API eklendiyse kısa bir doc comment yazıldı.
- [ ] README veya docs altındaki ilgili kısımlar güncellendi.
- [ ] Gerekli yerde hata mesajları `fmt.Errorf("...: %w", err)` formatında sarmalanıyor.

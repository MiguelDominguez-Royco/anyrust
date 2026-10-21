# 🔴 AnyRust — Escritorio Remoto Ultraligero en Rust

**AnyRust** es un clon nativo y ultraligero de **AnyDesk** desarrollado en **Rust** con `egui` / `eframe` y `tokio`. Permite compartir pantalla en tiempo real, controlar mouse y teclado remotamente, chatear en vivo y sincronizar el portapapeles en red local o VPN sin necesidad de servidores externos.

## ✨ Características Principales

- 🖥️ **Captura de Pantalla Nativa de Baja Latencia:** Usa la API GDI de Windows (`BitBlt` + `GetDIBits`) con indicador visual del cursor en tiempo real y compresión rápida `Zlib` (`flate2`).
- 🖱️ **Control Remoto de Mouse y Teclado:** Inyección directa de eventos de puntero (movimiento, clic izquierdo/derecho) y pulsaciones de teclado mediante `windows-sys`.
- 🔢 **ID de 9 Dígitos Estilo AnyDesk:** Genera automáticamente un identificador numérico de 9 dígitos (`XXX XXX XXX`) a partir de la IP local, además de permitir conexión directa por IP (`192.168.x.x` o `127.0.0.1`).
- 🔑 **PIN de Acceso Desatendido y Permisos en Vivo:** Configura un PIN de seguridad y activa o desactiva en tiempo real:
  - Conexiones entrantes
  - Control de Mouse y Teclado
  - Sincronización de Portapapeles
- 🎚️ **Selector de Calidad en Vivo:** Alterna entre **Alta HD (100%)**, **Equilibrada (50%)** y **Rápida (33%)** sin reiniciar la sesión.
- 💬 **Chat Integrado y Portapapeles:** Envía mensajes instantáneos y sincroniza texto copiado entre el anfitrión y el cliente.
- 🎨 **Temas Catppuccin Mocha (Oscuro) y Latte (Claro).**

## 🚀 Requisitos y Compilación

Asegúrate de tener instalado [Rust y Cargo](https://rustup.rs/).

```bash
# Clonar el repositorio
git clone https://github.com/MiguelDominguez-Royco/anyrust.git
cd anyrust

# Ejecutar en modo optimizado (Release)
cargo run --release
```

## 🔌 Puertos de Red

Por defecto, **AnyRust** escucha conexiones TCP entrantes en el puerto **`7890`** (con fallback automático del `7890` al `7900` si abres múltiples instancias en la misma PC), evitando colisiones con el puerto `7070` del servicio oficial de AnyDesk.

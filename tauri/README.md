# VRChat Scanner Desktop GUI

This is the official Desktop Graphical User Interface (GUI) for the `vrcstorage-scanner` project. It provides a native, fast, and user-friendly wrapper around the core Rust analysis engine, allowing non-technical users to seamlessly scan, analyze, and sanitize VRChat/Unity packages directly from their desktop.

## Architecture

The application is built using the [Tauri v2](https://v2.tauri.app/) framework. It bridges web technologies with native system performance:

- **Frontend**: A highly optimized, lightweight Single Page Application (SPA) built with Vanilla HTML, TypeScript, and Vite. We deliberately avoid heavy frontend frameworks (like React or Svelte) to keep the bundle size minimal and maximize performance. UI styling is powered by Tailwind CSS v4.
- **Backend (Core)**: A Rust-based backend powered by Tauri. It natively integrates the `vrcstorage-scanner` logic, executing heavy filesystem operations, recursive directory scanning, and the analysis pipeline with native system performance and safety.

## Project Structure

```text
tauri/
├── src/            # Frontend assets (TypeScript logic, Views, Utilities)
├── src-tauri/      # Backend (Rust code, Tauri configuration, System Capabilities)
├── index.html      # SPA entry point
├── package.json    # Node dependencies and build scripts
└── vite.config.ts  # Vite bundler configuration
```

## How to Build

### Prerequisites

To build and run the Tauri application, you need the following dependencies installed on your system:

1. [Node.js](https://nodejs.org/) (v18 or higher recommended)
2. [Rust](https://www.rust-lang.org/) (latest stable toolchain)
3. Native OS build tools:
   - **Windows**: Visual Studio C++ Build Tools
   - **macOS**: Xcode Command Line Tools
   - **Linux**: `build-essential`, `libwebkit2gtk-4.1-dev`, and other GTK dependencies.
   
*(For a comprehensive list of system-specific requirements, please refer to the official [Tauri Prerequisites Guide](https://v2.tauri.app/start/prerequisites/)).*

### Development Mode

To run the application in development mode, which includes hot-module reloading (HMR) for the frontend and automatic Rust recompilation:

1. Navigate to the `tauri` directory:
   ```bash
   cd tauri
   ```

2. Install the Node.js dependencies:
   ```bash
   npm install
   ```

3. Start the development environment:
   ```bash
   npm run tauri dev
   ```

### Production Build

To compile the application into a standalone, optimized executable or installer for your operating system:

1. Ensure you are in the `tauri` directory and dependencies are installed:
   ```bash
   cd tauri
   npm install
   ```

2. Run the Tauri build command:
   ```bash
   npm run tauri build
   ```

3. Once the build process is complete, the compiled executables and installers (e.g., `.exe` and `.msi` for Windows, `.app` and `.dmg` for macOS, `.deb` or `AppImage` for Linux) will be generated in the `tauri/src-tauri/target/release/bundle/` directory.

# TICS-TUI - TICS Isn't Closed Source

**TICS** is a free and open-source Terminal User Interface (TUI) frontend for **pyMC_Repeater**. Unlike proprietary alternatives, TICS is fully transparent, community-driven, and accessible to all users.

## Overview

TICS provides a modern, efficient TUI-based interface for managing and interacting with pyMC_Repeater. Built for users who prefer terminal-based workflows, it offers a lightweight and powerful alternative to closed-source frontends.

### Why TICS?

- **100% Open Source** - Full transparency and community contributions
- **Terminal Native** - Efficient TUI designed for modern terminal environments
- **Community Driven** - Built by and for the community
- **Accessible** - Free to use, modify, and distribute

## Features

- Intuitive TUI interface for pyMC_Repeater management
- Real-time monitoring and control
- Lightweight and fast performance
- Cross-platform compatibility
- Keyboard-driven navigation

## Installation

### Prerequisites
- Python 3.8 or higher
- pyMC_Repeater Installation
- pip (Python package installer)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/StrawbDevEmma/TICS-TUI.git
cd TICS

# Install TICS
pip install -e .

# Run TICS
tics
```

## Usage

Launch TICS from your terminal:

```bash
tics
```

Navigate using keyboard commands:
- Use arrow keys to navigate menus
- Press `Enter` to select options
- Press `q` or `Ctrl+C` to quit
- Press `?` or `h` for help

For detailed usage documentation, see [USAGE.md](USAGE.md).

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/StrawbDevEmma/TICS-TUI.git
cd TICS

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with dependencies
pip install -e ".[dev]"
```

### Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Reporting issues
- Submitting pull requests
- Coding standards
- Commit message conventions

### Running Tests

```bash
pytest
```

## Comparison with Alternatives

| Feature             | TICS | pyMC_Console | Default pyMC_Repeater UI |
|---------------------|:----:|:------------:|:------------------------:|
| Open Source         |  ✓   |      ✗       |        Partially         |
| Free                |  ✓   |      ✓       |            ✓             |
| Modifiable          |  ✓   |      ✗       |        Partially         |
| Community Driven    |  ✓   |      ✗       |        Partially         |
| Interface           | TUI  |     Web      |           Web            |

## Documentation

- [Installation Guide](docs/installation.md)
- [User Guide](docs/user-guide.md)
- [API Reference](docs/api-reference.md)
- [Contributing Guidelines](CONTRIBUTING.md)

## Support

- **Issues & Bug Reports**: [GitHub Issues](https://github.com/StrawbDevEmma/TICS/issues)
- **Discussions**: [GitHub Discussions](https://github.com/StrawbDevEmma/TICS/discussions)
- **Documentation**: Check the [docs](docs/) folder

## Roadmap

- [ ] v1.0 - Initial stable release
- [ ] Advanced filtering and search
- [ ] Custom theme support
- [ ] Performance monitoring dashboard
- [ ] Documentation

---
## Acknowledgments

TICS is built with:
- [pyMC_Repeater](https://github.com/pymc-devs/pymc_repeater) - The core API
- [Textual](https://github.com/Textualize/textual) - TUI framework## Roadmap

---
## License

This project is licensed under the **GNU General Public License Version 3** - see the [LICENSE](LICENSE) file for details.

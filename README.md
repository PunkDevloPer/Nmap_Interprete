# Nmap Interprete

Importador de hallazgos de herramientas de reconocimiento desde archivos de texto
o notas Markdown.

## Uso con salida Nmap

```bash
python3 nmapinterpreter.py -a escaneo.txt
```

Para obtener JSON:

```bash
python3 nmapinterpreter.py -a escaneo.txt --json
```

## Importar desde nota activa

Pega en una nota Markdown la salida de cualquiera de estas herramientas:

- Nmap
- ffuf
- feroxbuster
- nikto
- smbmap
- enum4linux
- whatweb

Despues ejecuta:

```bash
python3 nmapinterpreter.py --nota-activa "/ruta/a/nota.md" --actualizar-nota
```

El comando detecta todos los hallazgos compatibles y crea o reemplaza este bloque:

```markdown
<!-- security-imports:start -->
## Hallazgos importados
...
<!-- security-imports:end -->
```

Puedes volver a ejecutarlo sobre la misma nota: el bloque generado se reemplaza,
no se duplica.

## Un solo boton

El boton debe lanzar este comando pasando la ruta del archivo de la nota activa:

```bash
python3 /ruta/al/proyecto/nmapinterpreter.py --nota-activa "{{ruta_nota_activa}}" --actualizar-nota
```

En Obsidian, por ejemplo, esto puede conectarse con un plugin que ejecute comandos
externos y sustituya `{{ruta_nota_activa}}` por el path del archivo abierto.


# Header goes here

## How to Compile

### Prerequisites

```
Node14, Java11, Gradle6.9
```

### Steps

#### Node server
```
npm install
mkdir dist
npm run build
```

Run the server with `npm start`

#### Burp extension .jar

In the `burp/` dir:
```
gradle shadowJar
```

`burp/libs/burp-extension-web-app-flow-visualizer.jar` is created if successful. Import this .jar to Burp Extender.

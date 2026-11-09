// Planted examples: token in plain storage, WebView open to any site.
await AsyncStorage.setItem("authToken", token);
export const View = () => <WebView source={{ uri }} originWhitelist={["*"]} />;

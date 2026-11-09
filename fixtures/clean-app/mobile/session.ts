// Near misses: secure storage for the token, plain storage for a harmless setting, WebView limited to our site.
await SecureStore.setItemAsync("authToken", token);
await AsyncStorage.setItem("theme", "dark");
export const View = () => <WebView source={{ uri }} originWhitelist={["https://app.example.com"]} />;

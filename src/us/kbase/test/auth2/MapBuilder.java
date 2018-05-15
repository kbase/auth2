package us.kbase.test.auth2;

import java.util.HashMap;
import java.util.Map;

// http://stackoverflow.com/a/8879328/643675
public class MapBuilder<K,V> {

	private Map<K,V> map;

	public static <K,V> MapBuilder<K,V> newHashMap(){
		return new MapBuilder<K,V>(new HashMap<K,V>());
	}

	public MapBuilder(Map<K,V> map) {
		this.map = map;
	}

	public MapBuilder<K,V> with(K key, V value){
		map.put(key, value);
		return this;
	}

	public Map<K,V> build(){
		return map;
	}

}
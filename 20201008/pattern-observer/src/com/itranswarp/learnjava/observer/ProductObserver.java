package com.itranswarp.learnjava.observer;

public interface ProductObserver {

	void onPublished(Product product);

	void onPriceChanged(Product product);
}

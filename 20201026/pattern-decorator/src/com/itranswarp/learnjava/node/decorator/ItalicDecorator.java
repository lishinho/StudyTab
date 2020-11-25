package com.itranswarp.learnjava.node.decorator;

import com.itranswarp.learnjava.node.NodeDecorator;
import com.itranswarp.learnjava.node.TextNode;

public class ItalicDecorator extends NodeDecorator {

	public ItalicDecorator(TextNode target) {
		super(target);
	}

	@Override
	public String getText() {
		return "<i>" + target.getText() + "</i>";
	}
}

package com.itranswarp.learnjava.node.decorator;

import com.itranswarp.learnjava.node.NodeDecorator;
import com.itranswarp.learnjava.node.TextNode;

public class BoldDecorator extends NodeDecorator {

	public BoldDecorator(TextNode target) {
		super(target);
	}

	@Override
	public String getText() {
		return "<b>" + target.getText() + "</b>";
	}
}

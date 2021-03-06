/**
 * Copyright (c) 2014-2017 by the respective copyright holders.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
/*
 * generated by Xtext
 */
package org.eclipse.smarthome.model.persistence.ui.contentassist

import org.eclipse.emf.ecore.EObject
import org.eclipse.smarthome.core.items.GroupItem
import org.eclipse.smarthome.core.items.Item
import org.eclipse.smarthome.core.items.ItemRegistry
import org.eclipse.smarthome.designer.ui.UIActivator
import org.eclipse.xtext.Assignment
import org.eclipse.xtext.ui.editor.contentassist.ContentAssistContext
import org.eclipse.xtext.ui.editor.contentassist.ICompletionProposalAcceptor

/**
 * see http://www.eclipse.org/Xtext/documentation.html#contentAssist on how to customize content assistant
 */
class PersistenceProposalProvider extends AbstractPersistenceProposalProvider {

	override void completeGroupConfig_Group(EObject model, Assignment assignment,
			ContentAssistContext context, ICompletionProposalAcceptor acceptor) {
		super.completeGroupConfig_Group(model, assignment, context, acceptor);

		val registry = UIActivator.itemRegistryTracker.getService() as ItemRegistry
		if(registry!=null) {
			for(Item item : registry.getItems(context.getPrefix() + "*")) {
				if(item instanceof GroupItem) {
					val completionProposal = createCompletionProposal(item.getName(), context);
					acceptor.accept(completionProposal);
				}
			}
		}
	}
	
	override void completeItemConfig_Item(EObject model, Assignment assignment,
			ContentAssistContext context, ICompletionProposalAcceptor acceptor) {
		val registry = UIActivator.itemRegistryTracker.getService() as ItemRegistry
		if(registry!=null) {
			for(Item item : registry.getItems(context.getPrefix() + "*")) {
				val completionProposal = createCompletionProposal(item.getName(), context);
				acceptor.accept(completionProposal);
			}
		}
	}

}
